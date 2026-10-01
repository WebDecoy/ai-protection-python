"""Property-scoped shared quotas; raw account/session identities stay in-process."""

import asyncio
import hashlib
import hmac
import inspect
import re
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from .models import Check, FailureMode, Mode

_OPERATION = re.compile(
    r"[1-9][0-9]{9}\.[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\Z"
)


@dataclass(frozen=True)
class QuotaSubject:
    account_id: str = field(repr=False)
    session_id: str = field(default="", repr=False)


@dataclass(frozen=True)
class AccountQuota:
    rule_id: str
    subject_secret: str = field(repr=False)
    subject: Callable[[Any], QuotaSubject] = field(repr=False)
    limit: int
    window_seconds: int
    session_limit: int = 0
    mode: Mode = "observe"
    failure_mode: FailureMode = "open"
    timeout: float = 1.0
    idempotency: bool = False
    operation_id: Callable[[Any], str] | None = field(default=None, repr=False)


@dataclass(frozen=True)
class QuotaResult:
    check: Check
    allowed: bool = True
    status: int = 0
    retry_after_seconds: int = 0
    # Recovery receipt is for trusted application use only, never central telemetry.
    operation_id: str | None = field(default=None, repr=False)
    remaining: int | None = None
    reset_at: int | None = None


def new_quota_operation_id() -> str:
    """Persist in trusted state to recover the SAME admission within ten minutes.

    Reusing this receipt does not make model execution idempotent.
    """
    return f"{int(time.time())}.{uuid4()}"


def _utf8(value: Any, minimum: int, maximum: int | None = None) -> bool:
    if not isinstance(value, str):
        return False
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        return False
    return size >= minimum and (maximum is None or size <= maximum)


def _integer(value: Any, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _subject_hash(secret: str, *parts: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    for part in parts:
        value = part.encode("utf-8")
        digest.update(struct.pack("!I", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _validate_quota(quota: AccountQuota) -> None:
    from .client import _CODE, _duration

    if (
        not isinstance(quota, AccountQuota)
        or not isinstance(quota.rule_id, str)
        or not _CODE.fullmatch(quota.rule_id)
        or not _utf8(quota.subject_secret, 32)
        or not callable(quota.subject)
        or inspect.iscoroutinefunction(quota.subject)
        or not _integer(quota.limit, 1, 1000000)
        or not _integer(quota.window_seconds, 1, 86400)
        or not _integer(quota.session_limit, 0, quota.limit)
        or quota.mode not in ("observe", "enforce")
        or quota.failure_mode not in ("open", "closed")
        or not _duration(quota.timeout)
        or type(quota.idempotency) is not bool
        or (
            quota.operation_id is not None
            and (
                not quota.idempotency
                or not callable(quota.operation_id)
                or inspect.iscoroutinefunction(quota.operation_id)
            )
        )
    ):
        raise ValueError("invalid account quota configuration")


def _sync_call(callback, context):
    result = callback(context)
    if inspect.iscoroutine(result):
        result.close()
    if inspect.isawaitable(result):
        raise ValueError("quota callbacks must be synchronous")
    return result


async def _check_quota(client, quota: AccountQuota, context: Any) -> QuotaResult:
    from .client import _Unavailable

    started = time.monotonic()
    reason = "account_quota_unavailable"
    operation_id = None
    try:
        subject = _sync_call(quota.subject, context)
        if (
            not isinstance(subject, QuotaSubject)
            or not _utf8(subject.account_id, 1, 256)
            or not _utf8(subject.session_id, 1 if quota.session_limit else 0, 256)
        ):
            raise ValueError("invalid quota subject")
        parts = ("webdecoy.account-quota.v1", client._property_id, quota.rule_id)
        payload = {
            "schema": 2 if quota.idempotency else 1,
            "rule_id": quota.rule_id,
            "subject": _subject_hash(quota.subject_secret, *parts, "account", subject.account_id),
            "limit": quota.limit,
            "window_seconds": quota.window_seconds,
            "session_limit": quota.session_limit,
        }
        if quota.session_limit:
            payload["session"] = _subject_hash(
                quota.subject_secret,
                *parts,
                "session",
                subject.account_id,
                subject.session_id,
            )
        if quota.idempotency:
            candidate = (
                _sync_call(quota.operation_id, context)
                if quota.operation_id is not None
                else new_quota_operation_id()
            )
            if not isinstance(candidate, str) or not _OPERATION.fullmatch(candidate):
                raise ValueError("invalid quota operation ID")
            operation_id = candidate
            payload["operation_id"] = operation_id
    except Exception:  # noqa: BLE001 - sanitize application callback errors using quota failure policy
        payload = None

    if payload is not None:
        for _ in range(2 if quota.idempotency else 1):
            await asyncio.sleep(0)  # Cancellation never retries or becomes an allow decision.
            try:
                result = await client._json(
                    "POST",
                    "/api/v1/sdk/ai-abuse/quota",
                    payload,
                    quota.timeout,
                )
                allowed = result.get("allowed")
                retry = result.get("retry_after_seconds")
                if (
                    type(result.get("schema")) is not int
                    or result["schema"] != payload["schema"]
                    or (quota.idempotency and result.get("operation_id") != operation_id)
                    or type(allowed) is not bool
                    or not _integer(result.get("remaining"), 0, quota.limit)
                    or not _integer(result.get("reset_at"), 1, 2**63 - 1)
                    or not _integer(retry, 0, quota.window_seconds)
                    or (allowed and (result.get("reason") != "account_quota_allowed" or retry != 0))
                    or (
                        not allowed
                        and (result.get("reason") != "account_quota_exceeded" or retry < 1)
                    )
                ):
                    raise _Unavailable()
                deny = not allowed and quota.mode == "enforce"
                return QuotaResult(
                    Check(
                        "account_quota",
                        "shared",
                        quota.mode,
                        "allow" if allowed else "deny",
                        result["reason"],
                        (time.monotonic() - started) * 1000,
                    ),
                    not deny,
                    429 if deny else 0,
                    retry if deny else 0,
                    operation_id,
                    result["remaining"],
                    result["reset_at"],
                )
            except _Unavailable as exc:
                # Terminal responses must not restart admission with a fresh ID.
                # Keep an earlier unknown outcome even when recovery returns 410.
                if exc.status is not None and exc.status < 500:
                    break
                if quota.idempotency:
                    reason = "account_quota_outcome_unknown"
    deny = quota.mode == "enforce" and quota.failure_mode == "closed"
    return QuotaResult(
        Check(
            "account_quota",
            "shared",
            quota.mode,
            "unavailable",
            reason,
            (time.monotonic() - started) * 1000,
        ),
        not deny,
        503 if deny else 0,
        operation_id=operation_id,
    )
