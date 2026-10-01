"""Conservative reservations around exactly one awaited provider attempt."""

import asyncio
import math
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from .models import FailureMode, Mode
from .quota import AccountQuota, _integer, _subject_hash, _sync_call, _utf8, _validate_quota


@dataclass(frozen=True)
class BudgetLimits:
    account_tokens: int = 0
    account_micros: int = 0
    tenant_tokens: int = 0
    tenant_micros: int = 0
    feature_tokens: int = 0
    feature_micros: int = 0


@dataclass(frozen=True)
class BudgetSubject:
    account_id: str = field(repr=False)
    organization_id: str = field(repr=False)


@dataclass(frozen=True)
class BudgetPrice:
    provider: str
    model: str
    input_micros_per_million: int
    output_micros_per_million: int


@dataclass(frozen=True)
class BudgetUsage:
    provider: str
    model: str
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class BudgetCall:
    price_id: str
    max_input_tokens: int
    max_output_tokens: int
    request_id: str | None = None


@dataclass(frozen=True)
class BudgetRuntime:
    provider: str
    model: str
    max_input_tokens: int
    max_output_tokens: int


@dataclass(frozen=True)
class BudgetCompletion:
    value: Any = field(default=None, repr=False)
    usage: BudgetUsage | None = None


@dataclass(frozen=True)
class Budget:
    rule_id: str
    subject_secret: str = field(repr=False)
    subject: Callable[[Any], BudgetSubject] = field(repr=False)
    window_seconds: int
    limits: BudgetLimits
    prices: Mapping[str, BudgetPrice]
    mode: Mode = "observe"
    failure_mode: FailureMode = "open"
    timeout: float = 1.0
    max_runtime: float = 300.0

    def __post_init__(self):
        object.__setattr__(self, "prices", MappingProxyType(dict(self.prices)))


@dataclass(frozen=True)
class BudgetResult:
    call_id: str
    allowed: bool = True
    started: bool = False
    reserved: bool = False
    would_deny: bool = False
    overrun: bool = False
    status: int = 0
    retry_after_seconds: int = 0
    reason: str = "budget_unavailable"
    value: Any = field(default=None, repr=False)


def budget_cost(price: BudgetPrice, input_tokens: int, output_tokens: int) -> int:
    """Integer micro-USD, rounded up once across combined input/output cost."""
    if (
        not isinstance(price, BudgetPrice)
        or not _integer(input_tokens, 0, 10000000)
        or not _integer(output_tokens, 0, 10000000)
        or not _integer(price.input_micros_per_million, 0, 1000000000)
        or not _integer(price.output_micros_per_million, 0, 1000000000)
    ):
        raise ValueError("invalid budget usage or price")
    return (
        input_tokens * price.input_micros_per_million
        + output_tokens * price.output_micros_per_million
        + 999999
    ) // 1000000


def ollama_budget_usage(
    model: str, done: bool, input_tokens: int | None, output_tokens: int | None
):
    """Map final Ollama counts; missing counts are unknown, not zero."""
    if (
        done is not True
        or not _utf8(model, 1, 128)
        or not _integer(input_tokens, 0, 10000000)
        or not _integer(output_tokens, 0, 10000000)
    ):
        return None
    return BudgetUsage("ollama", model, input_tokens, output_tokens)


def _validate_budget(b):
    from .client import _CODE

    if not isinstance(b, Budget):
        raise TypeError("invalid budget configuration")
    _validate_quota(
        AccountQuota(
            b.rule_id,
            b.subject_secret,
            b.subject,
            1,
            b.window_seconds,
            mode=b.mode,
            failure_mode=b.failure_mode,
            timeout=b.timeout,
        )
    )
    if (
        not isinstance(b.limits, BudgetLimits)
        or type(b.max_runtime) not in (int, float)
        or not math.isfinite(b.max_runtime)
        or not 0 < b.max_runtime <= 900
        or not 1 <= len(b.prices) <= 64
    ):
        raise ValueError("invalid budget configuration")
    limits = asdict(b.limits).values()
    if not all(_integer(n, 0, 1000000000000) for n in limits) or not any(limits):
        raise ValueError("positive budget limit required")
    for key, price in b.prices.items():
        budget_cost(price, 0, 0)
        if (
            not isinstance(key, str)
            or not _CODE.fullmatch(key)
            or not isinstance(price.provider, str)
            or not _CODE.fullmatch(price.provider)
            or not _utf8(price.model, 1, 128)
        ):
            raise ValueError("invalid budget price")


async def _run_budget(client, b, context, call, work):
    from .client import _Unavailable, _valid_uuid

    client._check_loop()
    await asyncio.sleep(0)
    if not isinstance(call, BudgetCall) or not isinstance(call.price_id, str) or not callable(work):
        raise TypeError("budget call and deferred async work required")
    price = b.prices.get(call.price_id)
    micros = budget_cost(price, call.max_input_tokens, call.max_output_tokens)
    if call.max_input_tokens + call.max_output_tokens < 1 or (
        call.request_id is not None and not _valid_uuid(call.request_id)
    ):
        raise ValueError("positive token bounds and valid optional request ID required")
    out = BudgetResult(str(uuid4()))
    event = {
        "schema": 1,
        "call_id": out.call_id,
        "rule_id": b.rule_id,
        "mode": b.mode,
        "price_id": call.price_id,
        "input_rate": price.input_micros_per_million,
        "output_rate": price.output_micros_per_million,
        "reserved_tokens": call.max_input_tokens + call.max_output_tokens,
        "reserved_micros": micros,
    }
    if call.request_id is not None:
        event["request_id"] = call.request_id

    def report(phase, reason):
        client._queue_report(
            {
                **event,
                "phase": phase,
                "reason": reason,
                "timestamp": datetime.now(UTC).isoformat(),
                "started": out.started,
                "would_deny": out.would_deny,
            },
            "/api/v1/sdk/ai-abuse/usage",
        )

    async def rpc(payload):
        r = await client._json("POST", "/api/v1/sdk/ai-abuse/budget", payload, b.timeout)
        if (
            type(r.get("schema")) is not int
            or r["schema"] != 1
            or type(r.get("allowed")) is not bool
            or type(r.get("granted")) is not bool
            or type(r.get("overrun")) is not bool
            or not _integer(r.get("retry_after_seconds"), 0, 86400)
            or (r["granted"] and not _valid_uuid(r.get("reservation_id")))
        ):
            raise _Unavailable()
        return r

    try:
        grant = None
        body = {
            "schema": 1,
            "operation": "reserve",
            "rule_id": b.rule_id,
            "mode": b.mode,
            "nonce": out.call_id,
            "window_seconds": b.window_seconds,
            "limits": asdict(b.limits),
            "tokens": call.max_input_tokens + call.max_output_tokens,
            "micros": micros,
        }
        try:
            try:
                subject = _sync_call(b.subject, context)
                if (
                    not isinstance(subject, BudgetSubject)
                    or not _utf8(subject.account_id, 1, 256)
                    or not _utf8(subject.organization_id, 1, 256)
                ):
                    raise ValueError()
            except Exception:  # noqa: BLE001 - sanitize application callback failures
                raise _Unavailable() from None
            prefix = ("webdecoy.budget.v1", client._property_id, b.rule_id)
            body["subject"] = _subject_hash(
                b.subject_secret, *prefix, "account", subject.account_id
            )
            body["tenant"] = _subject_hash(
                b.subject_secret, *prefix, "tenant", subject.organization_id
            )
            candidate = await rpc(body)
            allowed, granted = candidate["allowed"], candidate["granted"]
            if granted:
                if candidate.get("reason") != (
                    "budget_allowed" if allowed else "budget_exceeded"
                ) or (not allowed and b.mode == "enforce"):
                    raise _Unavailable()
            elif allowed or candidate.get("reason") not in ("budget_exceeded", "budget_replay"):
                raise _Unavailable()
            grant = candidate
        except _Unavailable:
            if b.mode == "enforce" and b.failure_mode == "closed":
                out = replace(out, allowed=False, status=503)
                return out
        if grant is not None:
            if not grant["granted"]:
                out = replace(
                    out,
                    allowed=False,
                    status=429,
                    reason=grant["reason"],
                    retry_after_seconds=max(1, grant["retry_after_seconds"]),
                )
                return out
            event["reservation_id"] = grant["reservation_id"]
            out = replace(
                out, reserved=True, would_deny=not grant["allowed"], reason="budget_usage_unknown"
            )
        await asyncio.sleep(0)
        runtime = BudgetRuntime(
            price.provider, price.model, call.max_input_tokens, call.max_output_tokens
        )
        async with asyncio.timeout(b.max_runtime) as deadline:
            out = replace(out, started=True)
            report("start", "provider_attempt")
            completion = await work(runtime)
        # Even a callback that suppresses cancellation cannot claim known completion.
        if asyncio.current_task().cancelling():
            raise asyncio.CancelledError()
        if deadline.expired():
            raise TimeoutError("budget provider runtime exceeded")
        out = replace(
            out, value=completion.value if isinstance(completion, BudgetCompletion) else completion
        )
        usage = completion.usage if isinstance(completion, BudgetCompletion) else None
        if (
            not isinstance(usage, BudgetUsage)
            or usage.provider != price.provider
            or usage.model != price.model
        ):
            return out
        try:
            cost = budget_cost(price, usage.input_tokens, usage.output_tokens)
        except ValueError:
            return out
        event.update(
            input_tokens=usage.input_tokens, output_tokens=usage.output_tokens, cost_micros=cost
        )
        out = replace(
            out,
            overrun=usage.input_tokens > call.max_input_tokens
            or usage.output_tokens > call.max_output_tokens,
        )
        if not out.reserved:
            return out
        body = {k: v for k, v in body.items() if k != "nonce"}
        body.update(
            operation="settle",
            reservation_id=grant["reservation_id"],
            tokens=usage.input_tokens + usage.output_tokens,
            micros=cost,
        )
        out = replace(out, reason="budget_settlement_unavailable")
        try:
            settled = await rpc(body)
            if (
                settled["allowed"]
                and not settled["granted"]
                and settled.get("reason") == "budget_settled"
            ):
                out = replace(
                    out, reason="budget_settled", overrun=out.overrun or settled["overrun"]
                )
        except _Unavailable:
            pass
        return out
    except asyncio.CancelledError:
        # Usage fields must not accompany a cancelled event under the wire contract.
        for key in ("input_tokens", "output_tokens", "cost_micros"):
            event.pop(key, None)
        out = replace(out, reason="cancelled")
        raise
    except Exception:
        for key in ("input_tokens", "output_tokens", "cost_micros"):
            event.pop(key, None)
        out = replace(out, reason="provider_error")
        raise
    finally:
        report("finish", out.reason)
