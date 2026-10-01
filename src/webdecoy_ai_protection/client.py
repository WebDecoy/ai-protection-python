"""AsyncIO client. No prompts, model calls, or detection engine live here."""

import asyncio
import inspect
import ipaddress
import json
import logging
import math
import re
import time
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any, Self
from urllib.parse import urlsplit
from uuid import UUID, uuid4
from weakref import WeakKeyDictionary

import httpx

from .models import Check, Decision, FailureMode, Mode, Outcome, RequestMetadata, Rule, RuleResult
from .quota import AccountQuota, _check_quota, _validate_quota

_LOG = logging.getLogger("webdecoy_ai_protection")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_RESERVED = {"webdecoy", "browser_evidence", "account_quota", "concurrency"}
_MODES = ("observe", "enforce")
_FAILURES = ("open", "closed")
_UUID = re.compile(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\Z")


def _valid_uuid(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and UUID(value).int != 0


def _duration(value: float) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and 0 < value <= 10


class _Unavailable(Exception):
    def __init__(self, status: int | None = None):
        super().__init__("WebDecoy request unavailable")
        self.status = status


class Client:
    """Reuse one client per event loop/worker; drain handlers before closing it.

    Local rules must be cheap synchronous functions. Supplied test/custom transports
    must cooperate with cancellation; the built-in HTTPX transport does so.
    """

    def __init__(
        self,
        *,
        api_key: str,
        property_id: str,
        base_url: str = "https://ai-protection.webdecoy.com",
        mode: Mode = "observe",
        detector_failure_mode: FailureMode = "open",
        detector_timeout: float = 1.0,
        reporting_timeout: float = 1.0,
        max_pending_reports: int = 100,
        rules: Sequence[Rule] = (),
        reporting: bool = True,
        account_quota: AccountQuota | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        try:
            origin = urlsplit(base_url)
            _ = origin.port  # Validate malformed ports before constructing any transport.
        except (TypeError, ValueError):
            raise ValueError("invalid WebDecoy origin") from None
        if (
            not origin.hostname
            or origin.username is not None
            or origin.password is not None
            or origin.path not in ("", "/")
            or "?" in base_url
            or "#" in base_url
            or any(c.isspace() for c in base_url)
            or not (
                origin.scheme == "https"
                or (
                    origin.scheme == "http" and origin.hostname in ("localhost", "127.0.0.1", "::1")
                )
            )
        ):
            raise ValueError("WebDecoy origin must be HTTPS (HTTP only for loopback)")
        if not _valid_uuid(property_id) or not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("server API key and valid property ID required")
        if not api_key.isascii() or any(ord(c) < 33 or ord(c) == 127 for c in api_key):
            raise ValueError("invalid server API key")
        if (
            mode not in _MODES
            or detector_failure_mode not in _FAILURES
            or not _duration(detector_timeout)
            or not _duration(reporting_timeout)
            or type(max_pending_reports) is not int
            or not 1 <= max_pending_reports <= 10000
            or type(reporting) is not bool
        ):
            raise ValueError("invalid protection configuration")
        rules = tuple(rules)
        ids: set[str] = set()
        if len(rules) > 32:
            raise ValueError("at most 32 local rules")
        for rule in rules:
            if (
                not isinstance(rule, Rule)
                or not isinstance(rule.id, str)
                or not _CODE.fullmatch(rule.id)
                or rule.id in ids | _RESERVED
                or rule.mode not in _MODES
                or rule.failure_mode not in _FAILURES
                or not callable(rule.evaluate)
                or inspect.iscoroutinefunction(rule.evaluate)
            ):
                raise ValueError("invalid or duplicate synchronous local rule")
            ids.add(rule.id)
        if account_quota is not None:
            _validate_quota(account_quota)
        self._quota = account_quota
        self._base_url = base_url.rstrip("/")
        self._property_id = property_id.lower()
        self._mode = mode
        self._failure = detector_failure_mode
        self._timeout = detector_timeout
        self._report_timeout = reporting_timeout
        self._capacity = max_pending_reports
        self._rules = rules
        self._reporting = reporting
        self._http = httpx.AsyncClient(
            headers={
                "Authorization": "Bearer " + api_key,
                "X-WebDecoy-Property-ID": property_id,
                "Content-Type": "application/json",
                "Accept-Encoding": "identity",
            },
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        self._cached: dict[str, Any] = {"status": "unavailable"}
        self._until = 0.0
        self._binding_task: asyncio.Task | None = None
        self._pending: set[asyncio.Task] = set()
        self._issued: WeakKeyDictionary[Decision, bool] = WeakKeyDictionary()
        self._closed = False
        self._loop: asyncio.AbstractEventLoop | None = None

    def _check_loop(self) -> None:
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            raise RuntimeError("client must stay on one event loop")
        self._loop = loop
        if self._closed:
            raise RuntimeError("client is closed")

    async def _json(self, method: str, path: str, payload: Any, timeout: float) -> dict:
        try:
            body = None if payload is None else json.dumps(payload, allow_nan=False).encode()
            if body is not None and len(body) > 32768:
                raise _Unavailable()
            async with asyncio.timeout(timeout):
                async with self._http.stream(
                    method,
                    self._base_url + path,
                    content=body,
                    timeout=timeout,
                ) as response:
                    if not 200 <= response.status_code < 300:
                        raise _Unavailable(response.status_code)
                    # Reject compressed bodies to bound memory before decompression.
                    if response.headers.get("content-encoding", "identity").lower() not in (
                        "",
                        "identity",
                    ):
                        raise _Unavailable()
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(raw) + len(chunk) > 65536:
                            raise _Unavailable()
                        raw.extend(chunk)
                    value = json.loads(raw) if raw else {}
                    if not isinstance(value, dict):
                        raise _Unavailable()
                    return value
        except (httpx.HTTPError, TimeoutError, ValueError, UnicodeError, RecursionError):
            raise _Unavailable() from None

    async def _fetch_binding(self) -> dict:
        binding: dict[str, Any] = {"status": "unavailable"}
        try:
            value = await self._json("GET", "/api/v1/sdk/ai-abuse/config", None, self._timeout)
            if (
                type(value.get("schema")) is int
                and value["schema"] == 1
                and _valid_uuid(value.get("property_id"))
                and _valid_uuid(value.get("organization_id"))
                and value.get("mode") in _MODES
                and value.get("observe") is True
                and type(value.get("enforce")) is bool
            ):
                binding = {
                    **value,
                    "status": (
                        "verified"
                        if value["property_id"].lower() == self._property_id
                        else "property_mismatch"
                    ),
                }
        except _Unavailable:
            pass
        self._cached = binding
        self._until = time.monotonic() + (60 if binding["status"] == "verified" else 5)
        return binding

    async def _binding(self) -> dict:
        if time.monotonic() < self._until:
            return self._cached
        if self._binding_task is None or self._binding_task.done():
            self._binding_task = asyncio.create_task(self._fetch_binding())
        # Cancelling a waiter must not cancel the lookup used by other requests.
        return await asyncio.shield(self._binding_task)

    async def check(self, request: RequestMetadata, context: Any = None) -> Decision:
        self._check_loop()
        await asyncio.sleep(0)  # Honor already-requested cancellation before local work.
        if (
            not isinstance(request, RequestMetadata)
            or not isinstance(request.route, str)
            or not request.route.startswith("/")
            or len(request.route) > 512
            or any(c in request.route for c in "?#\r\n")
            or not isinstance(request.method, str)
            or not re.fullmatch(r"[A-Z]{1,16}", request.method)
        ):
            raise ValueError("HTTP method and normalized route required; no query or fragment")
        headers: dict[str, str] = {}
        if len(request.headers) > 100:
            raise ValueError("too many metadata headers")
        for name, value in request.headers.items():
            if (
                not isinstance(name, str)
                or not isinstance(value, str)
                or len(name) > 128
                or len(value) > 8192
            ):
                raise ValueError("invalid metadata headers")
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise ValueError("invalid metadata header name")
            # Explicit value allowlist. No cookie/auth values enter detection or reports.
            if name.lower() in {"user-agent", "accept-language", "accept-encoding"}:
                headers[name.lower()] = value
        checks: list[Check] = []
        allowed, reason, status, degraded = True, "allowed", 0, False
        for rule in self._rules:
            start = time.monotonic()
            verdict, why, denied_status = "allow", "rule_allowed", 403
            try:
                result = rule.evaluate(context)
                if inspect.iscoroutine(result):
                    result.close()
                if not isinstance(result, RuleResult) or type(result.allowed) is not bool:
                    raise ValueError()
                why = result.reason or ("rule_allowed" if result.allowed else "rule_denied")
                if (
                    not isinstance(why, str)
                    or not _CODE.fullmatch(why)
                    or result.status not in (403, 429)
                ):
                    raise ValueError()
                denied_status = result.status
                verdict = "allow" if result.allowed else "deny"
            except Exception:  # noqa: BLE001 - application callbacks obey configured failure policy
                verdict, why, denied_status = "unavailable", "local_rule_error", 503
                degraded = True
            checks.append(
                Check(rule.id, "local", rule.mode, verdict, why, (time.monotonic() - start) * 1000)
            )
            if (
                allowed
                and rule.mode == "enforce"
                and (
                    verdict == "deny"
                    or (verdict == "unavailable" and rule.failure_mode == "closed")
                )
            ):
                allowed, reason, status = False, why, denied_status
        quota_result = None
        if allowed and self._quota is not None:
            quota_result = await _check_quota(self, self._quota, context)
            checks.append(quota_result.check)
            degraded |= quota_result.check.decision == "unavailable"
            if not quota_result.allowed:
                allowed, reason, status = False, quota_result.check.reason, quota_result.status
        request_id = str(uuid4())
        remote = Check(
            "webdecoy",
            "remote",
            self._mode,
            "skipped",
            "account_quota_denial" if quota_result and not quota_result.allowed else "local_denial",
        )
        if allowed:
            try:
                if request.client_ip is not None and not isinstance(request.client_ip, str):
                    raise ValueError()
                ip = ipaddress.ip_address(request.client_ip or "")
                if getattr(ip, "scope_id", None):
                    raise ValueError()
                client_ip = str(getattr(ip, "ipv4_mapped", None) or ip)
            except ValueError:
                remote = Check("webdecoy", "remote", self._mode, "skipped", "client_ip_unavailable")
                degraded = True
            else:
                start = time.monotonic()
                binding = await self._binding()
                effective: Mode = (
                    self._mode
                    if (
                        binding["status"] == "verified"
                        and binding["enforce"]
                        and binding["mode"] == "enforce"
                    )
                    else "observe"
                )
                verdict, why = "unavailable", binding["status"]
                if binding["status"] == "verified":
                    payload = {
                        "decision_mode": "unified_v1",
                        "ai_admission": {"request_id": request_id, "mode": effective},
                        "request_metadata": {
                            "method": request.method,
                            "path": request.route,
                            "ip": client_ip,
                            "user_agent": headers.get("user-agent", ""),
                            "timestamp": int(time.time() * 1000),
                        },
                        "cs": {
                            "hn": sorted(name.lower() for name in request.headers),
                            "al": headers.get("accept-language", ""),
                            "ae": headers.get("accept-encoding", ""),
                        },
                        "local_analysis": {"needs_verification": True},
                    }
                    try:
                        result = await self._json(
                            "POST", "/api/v1/sdk/detect", payload, self._timeout
                        )
                        value = result.get("decision")
                        if result.get("decision_mode") != "unified_v1" or value not in (
                            "allow",
                            "block",
                            "challenge",
                        ):
                            raise _Unavailable()
                        verdict = "deny" if value == "block" else value
                        why = "detector_" + value
                        if effective == "enforce" and value != "allow":
                            allowed, reason, status = (
                                False,
                                (
                                    "verification_required"
                                    if value == "challenge"
                                    else "request_denied"
                                ),
                                403,
                            )
                    except _Unavailable:
                        verdict, why = "unavailable", "detector_unavailable"
                        if effective == "enforce" and self._failure == "closed":
                            allowed, reason, status = False, "protection_unavailable", 503
                remote = Check(
                    "webdecoy", "remote", effective, verdict, why, (time.monotonic() - start) * 1000
                )
                degraded |= verdict == "unavailable"
        checks.append(remote)
        await asyncio.sleep(0)
        decision = Decision(
            request_id,
            datetime.now(UTC).isoformat(),
            allowed,
            reason,
            status,
            degraded,
            tuple(checks),
            quota=quota_result,
            retry_after_seconds=quota_result.retry_after_seconds if quota_result else 0,
        )
        self._issued[decision] = False
        return decision

    def report(self, decision: Decision, outcome: Outcome | None = None) -> bool:
        self._check_loop()
        outcome = Outcome() if outcome is None else outcome
        if (
            not isinstance(outcome, Outcome)
            or (
                outcome.status is not None
                and (type(outcome.status) is not int or not 100 <= outcome.status <= 599)
            )
            or any(
                type(v) is not bool
                for v in (outcome.handler_attempted, outcome.cancelled, outcome.handler_error)
            )
        ):
            raise ValueError("invalid application outcome")
        if (
            not isinstance(decision, Decision)
            or decision not in self._issued
            or self._issued[decision]
        ):
            return False
        self._issued[decision] = True
        if not self._reporting:
            return False
        if len(self._pending) >= self._capacity:
            _LOG.warning("WebDecoy report dropped: queue full")
            return False
        action = (
            "forwarded"
            if decision.allowed
            else ("denied_unavailable" if decision.status == 503 else "denied")
        )
        if outcome.cancelled:
            action = "cancelled"
        elif outcome.handler_error:
            action = "handler_error"
        payload = {
            "schema": 1,
            "request_id": decision.id,
            "timestamp": decision.timestamp,
            "decision": "allow" if decision.allowed else "deny",
            "reason": decision.reason,
            "degraded": decision.degraded,
            "checks": [asdict(c) for c in decision.checks],
            "handler_attempted": outcome.handler_attempted,
            "action": action,
        }
        if outcome.status is not None:
            payload["handler_status"] = outcome.status
        task = asyncio.create_task(self._send_report(payload))
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)
        return True

    async def _send_report(self, payload: dict) -> None:
        try:
            await self._json("POST", "/api/v1/sdk/ai-abuse/reports", payload, self._report_timeout)
        except _Unavailable:
            _LOG.warning("WebDecoy report delivery failed")

    async def flush(self) -> None:
        self._check_loop()
        if self._pending:
            await asyncio.shield(asyncio.gather(*tuple(self._pending)))

    async def aclose(self) -> None:
        if self._closed:
            return
        self._check_loop()
        self._closed = True
        # Application must drain incoming handlers first. No new reports after this point.
        try:
            tasks = tuple(self._pending)
            if tasks:
                await asyncio.gather(*tasks)
        finally:
            if self._binding_task is not None and not self._binding_task.done():
                self._binding_task.cancel()
                await asyncio.gather(self._binding_task, return_exceptions=True)
            for task in tuple(self._pending):
                task.cancel()
            await asyncio.gather(*tuple(self._pending), return_exceptions=True)
            await self._http.aclose()

    async def __aenter__(self) -> Self:
        self._check_loop()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()
