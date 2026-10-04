"""Exercise the real Ollama SDK HTTP serialization and response parsing offline."""

import asyncio
import json
import unittest

import httpx
from ollama import AsyncClient, ResponseError
from test_budget import BudgetFixture, policy

from examples.ollama_budget import MODEL, generate
from webdecoy_ai_protection import BudgetPrice


class OllamaExampleTests(unittest.IsolatedAsyncioTestCase):
    async def run_example(self, payload=None, *, override=None, error=False, cancel=False):
        fixture = BudgetFixture()
        fixture.override.update(override or {})
        calls = []

        async def handle(request):
            calls.append(json.loads(request.content))
            self.assertEqual(request.url.path, "/api/generate")
            self.assertEqual(len(fixture.budget_calls), 1)  # reserve before inference
            if cancel:
                raise asyncio.CancelledError()
            if error:
                return httpx.Response(500, json={"error": "provider unavailable"})
            return httpx.Response(
                200,
                json=payload
                or {
                    "model": MODEL,
                    "done": True,
                    "response": "private answer",
                    "prompt_eval_count": 12,
                    "eval_count": 4,
                },
            )

        provider = AsyncClient(host="http://localhost:11434", transport=httpx.MockTransport(handle))
        config = policy(prices={"local": BudgetPrice("ollama", MODEL, 0, 0)}, mode="enforce")
        async with fixture.client(budget=config) as client:
            try:
                result = await generate(client, provider, None, "private prompt")
            except (ResponseError, asyncio.CancelledError) as exc:
                result = exc
            await client.flush()
        return result, fixture, calls

    async def test_real_sdk_request_and_final_usage_privacy(self):
        result, fixture, calls = await self.run_example()
        self.assertEqual(result.value, "private answer")
        self.assertEqual(result.reason, "budget_settled")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["model"], MODEL)
        self.assertTrue(calls[0]["raw"])
        self.assertFalse(calls[0]["stream"])
        self.assertEqual(calls[0]["options"], {"num_ctx": 2048, "num_predict": 128})
        self.assertEqual(fixture.budget_calls[0]["tokens"], 2176)
        self.assertEqual(fixture.budget_calls[1]["tokens"], 16)
        wire = json.dumps([fixture.budget_calls, fixture.usage])
        self.assertNotIn("private prompt", wire)
        self.assertNotIn("private answer", wire)

    async def test_denial_never_calls_provider(self):
        result, fixture, calls = await self.run_example(
            override={
                "reserve": {
                    "schema": 1,
                    "allowed": False,
                    "granted": False,
                    "overrun": False,
                    "reason": "budget_exceeded",
                    "retry_after_seconds": 30,
                }
            }
        )
        self.assertEqual(result.status, 429)
        self.assertEqual(calls, [])
        self.assertEqual(len(fixture.budget_calls), 1)

    async def test_unknown_or_wrong_model_retains_reservation(self):
        for fields in (
            {},
            {"prompt_eval_count": 12},
            {"model": "other", "prompt_eval_count": 12, "eval_count": 4},
            {"done": False, "prompt_eval_count": 12, "eval_count": 4},
        ):
            with self.subTest(fields=fields):
                result, fixture, calls = await self.run_example(
                    {
                        "model": MODEL,
                        "done": True,
                        "response": "answer",
                        **fields,
                    }
                )
                self.assertEqual(result.value, "answer")
                self.assertEqual(result.reason, "budget_usage_unknown")
                self.assertEqual(len(fixture.budget_calls), 1)
                self.assertEqual(len(calls), 1)

    async def test_explicit_zero_settles(self):
        result, fixture, _ = await self.run_example(
            {
                "model": MODEL,
                "done": True,
                "response": "",
                "prompt_eval_count": 0,
                "eval_count": 0,
            }
        )
        self.assertEqual(result.reason, "budget_settled")
        self.assertEqual(fixture.budget_calls[-1]["tokens"], 0)

    async def test_accounting_outage_keeps_output_without_retry(self):
        result, fixture, calls = await self.run_example(override={"settle": 503})
        self.assertEqual(result.value, "private answer")
        self.assertEqual(result.reason, "budget_settlement_unavailable")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(fixture.budget_calls), 2)

    async def test_error_and_cancellation_never_settle_or_retry(self):
        for options, exception in (
            ({"error": True}, ResponseError),
            ({"cancel": True}, asyncio.CancelledError),
        ):
            result, fixture, calls = await self.run_example(**options)
            self.assertIsInstance(result, exception)
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(fixture.budget_calls), 1)

    async def test_input_bound_before_reservation(self):
        fixture = BudgetFixture()
        async with fixture.client(budget=policy()) as client:
            with self.assertRaises(ValueError):
                await generate(client, None, None, "a" * 1025)
        self.assertEqual(fixture.budget_calls, [])
