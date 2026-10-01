import asyncio
import json
import unittest
from dataclasses import replace

import httpx
from test_client import PROPERTY, Fixture

from webdecoy_ai_protection import (
    Budget,
    BudgetCall,
    BudgetCompletion,
    BudgetLimits,
    BudgetPrice,
    BudgetSubject,
    BudgetUsage,
    Client,
    budget_cost,
    ollama_budget_usage,
)

RESERVATION = "44444444-4444-4444-8444-444444444444"
PRICE = BudgetPrice("ollama", "fixture", 1000000, 2000000)
CALL = BudgetCall("local", 10, 20, PROPERTY)
USAGE = BudgetUsage("ollama", "fixture", 3, 4)


def policy(**changes):
    return replace(
        Budget(
            "chat",
            "x" * 32,
            lambda _: BudgetSubject("private-account", "private-org"),
            60,
            BudgetLimits(account_tokens=100),
            {"local": PRICE},
        ),
        **changes,
    )


class BudgetFixture(Fixture):
    def __init__(self):
        super().__init__()
        self.budget_calls = []
        self.usage = []
        self.override = {}
        self.reserve_entered = asyncio.Event()
        self.reserve_gate = None
        self.usage_gate = None

    async def handle(self, request):
        body = json.loads(request.content or b"{}")
        if request.url.path.endswith("/usage"):
            self.usage.append(body)
            if self.usage_gate:
                await self.usage_gate.wait()
            return httpx.Response(202, json={"accepted": True})
        if not request.url.path.endswith("/budget"):
            return await super().handle(request)
        self.budget_calls.append(body)
        operation = body["operation"]
        if operation == "reserve":
            self.reserve_entered.set()
            if self.reserve_gate:
                await self.reserve_gate.wait()
        override = self.override.get(operation)
        if override is not None:
            return (
                httpx.Response(override)
                if isinstance(override, int)
                else httpx.Response(200, json=override)
            )
        return httpx.Response(
            200,
            json={
                "schema": 1,
                "allowed": True,
                "granted": operation == "reserve",
                "reason": "budget_allowed" if operation == "reserve" else "budget_settled",
                "reservation_id": RESERVATION,
                "retry_after_seconds": 0,
                "overrun": False,
            },
        )


class BudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_reserve_settle_privacy_and_usage_correlation(self):
        f = BudgetFixture()

        async def work(runtime):
            self.assertEqual(
                (
                    runtime.provider,
                    runtime.model,
                    runtime.max_input_tokens,
                    runtime.max_output_tokens,
                ),
                ("ollama", "fixture", 10, 20),
            )
            return BudgetCompletion("private-model-output", USAGE)

        async with f.client(budget=policy()) as c:
            r = await c.run_budget({"prompt": "private-prompt"}, CALL, work)
            await c.flush()
        self.assertEqual(r.value, "private-model-output")
        self.assertEqual(r.reason, "budget_settled")
        self.assertTrue(r.started and r.reserved)
        reserve, settle = f.budget_calls
        self.assertEqual((reserve["tokens"], reserve["micros"]), (30, 50))
        self.assertEqual((settle["tokens"], settle["micros"]), (7, 11))
        self.assertNotIn("nonce", settle)
        self.assertEqual([e["phase"] for e in f.usage], ["start", "finish"])
        self.assertEqual(f.usage[0]["call_id"], r.call_id)
        self.assertEqual(f.usage[1]["request_id"], PROPERTY)
        self.assertNotIn("input_tokens", f.usage[0])
        self.assertEqual(f.usage[1]["cost_micros"], 11)
        for secret in (
            "private-model-output",
            "private-prompt",
            "private-account",
            "private-org",
            "x" * 32,
        ):
            self.assertNotIn(secret, json.dumps([f.budget_calls, f.usage]))

    async def test_denial_and_replay_never_start_even_in_observe(self):
        for reason in ("budget_exceeded", "budget_replay"):
            f = BudgetFixture()
            f.override["reserve"] = {
                "schema": 1,
                "allowed": False,
                "granted": False,
                "reason": reason,
                "retry_after_seconds": 30,
                "overrun": False,
            }

            async def work(_):
                self.fail("denied attempt started")

            async with f.client(budget=policy()) as c:
                r = await c.run_budget(None, CALL, work)
                await c.flush()
            self.assertEqual(r.status, 429)
            self.assertFalse(r.started)
            self.assertEqual(len(f.usage), 1)
            self.assertFalse(f.usage[0]["started"])

    async def test_observe_exceeded_grant_and_overrun(self):
        f = BudgetFixture()
        f.override["reserve"] = {
            "schema": 1,
            "allowed": False,
            "granted": True,
            "reason": "budget_exceeded",
            "retry_after_seconds": 30,
            "reservation_id": RESERVATION,
            "overrun": False,
        }

        async def work(_):
            return BudgetCompletion("original", replace(USAGE, output_tokens=21))

        async with f.client(budget=policy()) as c:
            r = await c.run_budget(None, CALL, work)
        self.assertTrue(r.would_deny and r.overrun)
        self.assertEqual(r.reason, "budget_settled")

    async def test_state_failure_matrix_preserves_output_without_reservation(self):
        for mode in ("observe", "enforce"):
            for failure in ("open", "closed"):
                f = BudgetFixture()
                f.override["reserve"] = 503
                calls = []

                async def work(_, calls=calls):
                    calls.append(True)
                    return BudgetCompletion("result", USAGE)

                async with f.client(budget=policy(mode=mode, failure_mode=failure)) as c:
                    r = await c.run_budget(None, CALL, work)
                    await c.flush()
                deny = mode == "enforce" and failure == "closed"
                self.assertEqual(r.allowed, not deny)
                self.assertEqual(len(calls), int(not deny))
                self.assertFalse(r.reserved)
                self.assertEqual(len(f.budget_calls), 1)
                self.assertEqual(f.usage[-1]["reason"], "budget_unavailable")

    async def test_unknown_usage_retains_maximum_and_never_refunds(self):
        for usage in (
            None,
            replace(USAGE, provider="other"),
            replace(USAGE, model="other"),
            replace(USAGE, input_tokens=True),
            replace(USAGE, output_tokens=-1),
        ):
            f = BudgetFixture()

            async def work(_, usage=usage):
                return BudgetCompletion("result", usage)

            async with f.client(budget=policy()) as c:
                r = await c.run_budget(None, CALL, work)
                await c.flush()
            self.assertEqual(r.reason, "budget_usage_unknown")
            self.assertEqual(r.value, "result")
            self.assertEqual(len(f.budget_calls), 1)
            self.assertNotIn("input_tokens", f.usage[-1])

    async def test_settlement_failure_never_raises_or_retries_provider(self):
        for response in (503, {"schema": 1}):
            f = BudgetFixture()
            f.override["settle"] = response
            calls = []

            async def work(_, calls=calls):
                calls.append(True)
                return BudgetCompletion("original", USAGE)

            async with f.client(budget=policy()) as c:
                r = await c.run_budget(None, CALL, work)
                await c.flush()
            self.assertEqual(r.reason, "budget_settlement_unavailable")
            self.assertEqual(r.value, "original")
            self.assertEqual(calls, [True])
            self.assertEqual(len(f.budget_calls), 2)
            self.assertEqual(f.usage[-1]["cost_micros"], 11)

    async def test_cancel_error_and_timeout_retain_reservation(self):
        for kind in ("cancel", "error", "timeout", "suppressed_timeout"):
            f = BudgetFixture()
            entered = asyncio.Event()

            async def work(_, kind=kind, entered=entered):
                entered.set()
                if kind == "error":
                    raise ValueError("private-provider-error")
                try:
                    await asyncio.sleep(10)
                except asyncio.CancelledError:
                    if kind != "suppressed_timeout":
                        raise
                return BudgetCompletion("late", USAGE)

            async with f.client(budget=policy(max_runtime=0.02)) as c:
                task = asyncio.create_task(c.run_budget(None, CALL, work))
                await entered.wait()
                if kind == "cancel":
                    task.cancel()
                expected = (
                    asyncio.CancelledError
                    if kind == "cancel"
                    else ValueError
                    if kind == "error"
                    else TimeoutError
                )
                with self.assertRaises(expected):
                    await task
                await c.flush()
            self.assertEqual(len(f.budget_calls), 1)
            self.assertNotIn("input_tokens", f.usage[-1])
            self.assertNotIn("private-provider-error", json.dumps(f.usage))

    async def test_cancel_during_reserve_never_invokes_model(self):
        f = BudgetFixture()
        f.reserve_gate = asyncio.Event()

        async def work(_):
            self.fail("cancelled reservation invoked work")

        async with f.client(budget=policy()) as c:
            task = asyncio.create_task(c.run_budget(None, CALL, work))
            await f.reserve_entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await c.flush()
        self.assertEqual(len(f.budget_calls), 1)
        self.assertFalse(f.usage[-1]["started"])
        self.assertEqual(f.usage[-1]["reason"], "cancelled")

    async def test_rounding_explicit_zero_and_ollama_final_counts(self):
        self.assertEqual(budget_cost(BudgetPrice("x", "x", 1, 1), 1, 1), 1)
        self.assertIsNone(ollama_budget_usage("fixture", True, None, 0))
        self.assertIsNone(ollama_budget_usage("fixture", False, 1, 2))
        self.assertIsNone(ollama_budget_usage("fixture", True, True, 2))
        zero = ollama_budget_usage("fixture", True, 0, 0)
        f = BudgetFixture()

        async def work(_):
            return BudgetCompletion("empty", zero)

        async with f.client(budget=policy()) as c:
            r = await c.run_budget(None, CALL, work)
        self.assertEqual(r.reason, "budget_settled")
        self.assertEqual(f.budget_calls[-1]["tokens"], 0)

    async def test_invalid_config_and_price_mapping_snapshot(self):
        prices = {"local": PRICE}
        b = policy(prices=prices)
        prices.clear()
        self.assertEqual(b.prices["local"], PRICE)
        for changes in (
            {"limits": BudgetLimits()},
            {"max_runtime": float("nan")},
            {"limits": BudgetLimits(account_tokens=True)},
            {"prices": {}},
            {"prices": {"bad": replace(PRICE, input_micros_per_million=-1)}},
        ):
            with self.assertRaises(ValueError):
                Client(api_key="fixture", property_id=PROPERTY, budget=policy(**changes))

    async def test_reporting_queue_bound_and_separate_attempt_ids(self):
        f = BudgetFixture()
        f.usage_gate = asyncio.Event()

        async def work(_):
            await asyncio.sleep(0)
            return BudgetCompletion("ok", USAGE)

        async with f.client(budget=policy(), max_pending_reports=1, reporting_timeout=0.01) as c:
            with self.assertLogs("webdecoy_ai_protection", level="WARNING"):
                first = await c.run_budget(None, CALL, work)
                second = await c.run_budget(None, CALL, work)
                self.assertLessEqual(len(c._pending), 1)
                await c.flush()
        self.assertNotEqual(first.call_id, second.call_id)
        self.assertEqual(first.reason, "budget_settled")
        self.assertEqual(second.reason, "budget_settled")

    async def test_malformed_reservation_never_starts_closed_work(self):
        base = {
            "schema": 1,
            "allowed": True,
            "granted": True,
            "reason": "budget_allowed",
            "reservation_id": RESERVATION,
            "retry_after_seconds": 0,
            "overrun": False,
        }
        for change in (
            {"schema": True},
            {"granted": 1},
            {"allowed": False},
            {"reservation_id": "bad"},
            {"overrun": 0},
            {"retry_after_seconds": -1},
            {"reason": "other"},
        ):
            f = BudgetFixture()
            f.override["reserve"] = {**base, **change}

            async def work(_):
                self.fail("malformed reservation ran provider")

            async with f.client(budget=policy(mode="enforce", failure_mode="closed")) as c:
                r = await c.run_budget(None, CALL, work)
            self.assertEqual(r.status, 503)
            self.assertEqual(len(f.budget_calls), 1)

    async def test_stream_consumed_before_final_usage_settlement(self):
        f = BudgetFixture()
        chunks = []

        async def stream():
            yield {"text": "first", "done": False}
            await asyncio.sleep(0)
            self.assertEqual(len(f.budget_calls), 1)
            yield {"text": "last", "done": True, "prompt_eval_count": 3, "eval_count": 4}

        async def work(runtime):
            usage = None
            async for chunk in stream():
                chunks.append(chunk["text"])
                if chunk["done"]:
                    usage = ollama_budget_usage(
                        runtime.model,
                        chunk["done"],
                        chunk.get("prompt_eval_count"),
                        chunk.get("eval_count"),
                    )
            return BudgetCompletion("".join(chunks), usage)

        async with f.client(budget=policy()) as c:
            result = await c.run_budget(None, CALL, work)
        self.assertEqual(result.value, "firstlast")
        self.assertEqual(result.reason, "budget_settled")
