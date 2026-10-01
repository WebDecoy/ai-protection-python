"""Shared lease ownership for one awaited unit of expensive work."""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any
from uuid import uuid4

from .models import Check, FailureMode, Mode
from .quota import (
    AccountQuota,
    QuotaSubject,
    _integer,
    _subject_hash,
    _sync_call,
    _utf8,
    _validate_quota,
)


@dataclass(frozen=True)
class Concurrency:
    rule_id: str
    subject_secret: str = field(repr=False)
    subject: Callable[[Any], QuotaSubject] = field(repr=False)
    account_limit: int
    feature_limit: int
    ttl_seconds: int = 30
    max_seconds: int = 300
    mode: Mode = "observe"
    failure_mode: FailureMode = "open"
    timeout: float = 1.0


@dataclass(frozen=True)
class ConcurrencyResult:
    allowed: bool
    check: Check
    status: int = 0
    retry_after_seconds: int = 0
    # Release failure is an outcome, never an instruction to retry provider work.
    leased: bool = False
    released: bool = False
    value: Any = field(default=None, repr=False)


class ConcurrencyLeaseLost(RuntimeError):
    """Owned work was cancelled because renewal or the maximum runtime failed."""


def _validate_concurrency(q: Concurrency) -> None:
    if not isinstance(q, Concurrency):
        raise TypeError("invalid concurrency configuration")
    _validate_quota(
        AccountQuota(
            q.rule_id,
            q.subject_secret,
            q.subject,
            1,
            1,
            mode=q.mode,
            failure_mode=q.failure_mode,
            timeout=q.timeout,
        )
    )
    if (
        not _integer(q.account_limit, 1, 1000)
        or not _integer(q.feature_limit, q.account_limit, 10000)
        or not _integer(q.ttl_seconds, 6, 120)
        or not _integer(q.max_seconds, q.ttl_seconds, 900)
        or q.timeout > q.ttl_seconds / 6
    ):
        raise ValueError("invalid concurrency configuration")


async def _run_concurrent(client, q, context, work, on_admission=None):
    from .client import _Unavailable, _valid_uuid

    client._check_loop()
    if not callable(work):
        raise TypeError("deferred async work required")
    await asyncio.sleep(0)
    started = time.monotonic()
    body = {
        "schema": 1,
        "operation": "acquire",
        "rule_id": q.rule_id,
        "mode": q.mode,
        "nonce": str(uuid4()),
        "account_limit": q.account_limit,
        "feature_limit": q.feature_limit,
        "ttl_seconds": q.ttl_seconds,
        "max_seconds": q.max_seconds,
    }

    async def rpc(payload):
        r = await client._json("POST", "/api/v1/sdk/ai-abuse/concurrency", payload, q.timeout)
        if (
            type(r.get("schema")) is not int
            or r["schema"] != 1
            or type(r.get("allowed")) is not bool
            or type(r.get("granted")) is not bool
            or not _integer(r.get("retry_after_seconds"), 0, q.max_seconds)
            or (
                r["granted"]
                and (
                    not _valid_uuid(r.get("lease_id"))
                    or not _integer(r.get("valid_for_ms"), 1, q.ttl_seconds * 1000)
                )
            )
        ):
            raise _Unavailable()
        return r

    grant = None
    try:
        try:
            subject = _sync_call(q.subject, context)
            if not isinstance(subject, QuotaSubject) or not _utf8(subject.account_id, 1, 256):
                raise ValueError()
        except Exception:  # noqa: BLE001 - sanitize application callback errors
            raise _Unavailable() from None
        body["subject"] = _subject_hash(
            q.subject_secret,
            "webdecoy.account-quota.v1",
            client._property_id,
            q.rule_id,
            "account",
            subject.account_id,
        )
        candidate = await rpc(body)
        allowed, granted, reason = (
            candidate["allowed"],
            candidate["granted"],
            candidate.get("reason"),
        )
        if granted:
            if reason != ("concurrency_allowed" if allowed else "concurrency_exceeded") or (
                not allowed and q.mode == "enforce"
            ):
                raise _Unavailable()
        elif allowed or reason not in ("concurrency_exceeded", "concurrency_replay"):
            raise _Unavailable()
        grant = candidate
    except _Unavailable:
        pass
    duration = (time.monotonic() - started) * 1000
    if grant is None:
        denied = q.mode == "enforce" and q.failure_mode == "closed"
        result = ConcurrencyResult(
            not denied,
            Check(
                "concurrency", "shared", q.mode, "unavailable", "concurrency_unavailable", duration
            ),
            status=503 if denied else 0,
        )
    else:
        result = ConcurrencyResult(
            grant["granted"],
            Check(
                "concurrency",
                "shared",
                q.mode,
                "allow" if grant["allowed"] else "deny",
                grant["reason"],
                duration,
            ),
            leased=grant["granted"],
            status=0 if grant["granted"] else 429,
            retry_after_seconds=0 if grant["granted"] else max(1, grant["retry_after_seconds"]),
        )
    deadline = started + grant["valid_for_ms"] / 1000 if grant and grant["granted"] else 0
    if result.allowed and grant and deadline - time.monotonic() <= q.timeout:
        result = replace(
            result,
            allowed=False,
            status=503,
            check=Check(
                "concurrency", "shared", q.mode, "unavailable", "concurrency_lease_lost", duration
            ),
        )
    if on_admission is not None:
        on_admission(result)
    if not result.allowed:
        return result
    await asyncio.sleep(0)
    lease_body = {k: v for k, v in body.items() if k != "nonce"}
    if grant:
        lease_body["lease_id"] = grant["lease_id"]

    async def heartbeat():
        nonlocal deadline
        end = started + q.max_seconds
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise ConcurrencyLeaseLost("concurrency maximum runtime reached")
            if grant is None:
                await asyncio.sleep(remaining)
                continue
            delay = min(q.ttl_seconds / 3, (deadline - time.monotonic()) / 3, remaining)
            if delay <= 0:
                raise ConcurrencyLeaseLost("concurrency lease expired")
            await asyncio.sleep(delay)
            sent = time.monotonic()
            if sent >= end:
                raise ConcurrencyLeaseLost("concurrency maximum runtime reached")
            try:
                async with asyncio.timeout(max(0, min(deadline - sent - 0.1, end - sent))):
                    renewed = await rpc({**lease_body, "operation": "renew"})
                if (
                    not renewed["granted"]
                    or not renewed["allowed"]
                    or renewed["lease_id"] != grant["lease_id"]
                    or renewed.get("reason") != "concurrency_renewed"
                ):
                    raise _Unavailable()
                deadline = min(end, sent + renewed["valid_for_ms"] / 1000)
            except (_Unavailable, TimeoutError):
                raise ConcurrencyLeaseLost("concurrency renewal unavailable") from None

    async def invoke():
        await asyncio.sleep(0)
        if time.monotonic() >= started + q.max_seconds or (grant and time.monotonic() >= deadline):
            raise ConcurrencyLeaseLost("concurrency lease expired before work")
        return await work()

    monitor = asyncio.create_task(heartbeat())
    task = asyncio.create_task(invoke())
    try:
        done, _ = await asyncio.wait((monitor, task), return_when=asyncio.FIRST_COMPLETED)
        if monitor in done:
            await monitor  # Raises even if work suppressed cancellation and returned a value.
        value = await task
        if time.monotonic() >= started + q.max_seconds or (grant and time.monotonic() >= deadline):
            raise ConcurrencyLeaseLost("concurrency lease expired")
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        released = False
        if grant:
            try:
                release = await rpc({**lease_body, "operation": "release"})
                released = (
                    release["allowed"]
                    and not release["granted"]
                    and release.get("reason") == "concurrency_released"
                )
            except _Unavailable:
                pass
        return replace(result, value=value, released=released)
    finally:
        # Errors/cancellation never claim provider completion or release capacity.
        for pending in (task, monitor):
            pending.cancel()
        await asyncio.gather(task, monitor, return_exceptions=True)
