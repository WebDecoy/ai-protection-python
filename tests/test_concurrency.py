import asyncio
import json
import unittest
from dataclasses import replace

import httpx
import test_fastapi as fastapi_fixture
from test_client import PROPERTY, Fixture

from webdecoy_ai_protection import Client, Concurrency, ConcurrencyLeaseLost, QuotaSubject

LEASE = "33333333-3333-4333-8333-333333333333"


def policy(**changes):
    return replace(
        Concurrency(
            "chat_v1",
            "x" * 32,
            lambda _: QuotaSubject("private-account"),
            1,
            5,
            ttl_seconds=6,
            max_seconds=6,
            timeout=0.01,
        ),
        **changes,
    )


class LeaseFixture(Fixture):
    def __init__(self):
        super().__init__()
        self.lease_calls = []
        self.overrides = {}
        self.granted = True
        self.allowed = True
        self.reason = "concurrency_allowed"
        self.valid_for = 6000
        self.acquiring = asyncio.Event()
        self.acquire_gate = None
        self.renewed = asyncio.Event()

    async def handle(self, request):
        if not request.url.path.endswith("/concurrency"):
            return await super().handle(request)
        body = json.loads(request.content)
        self.lease_calls.append(body)
        operation = body["operation"]
        if operation == "acquire":
            self.acquiring.set()
            if self.acquire_gate:
                await self.acquire_gate.wait()
        if operation == "renew":
            self.renewed.set()
        override = self.overrides.get(operation)
        if override is not None:
            return (
                httpx.Response(override)
                if isinstance(override, int)
                else httpx.Response(200, json=override)
            )
        release = operation == "release"
        return httpx.Response(
            200,
            json={
                "schema": 1,
                "allowed": True if operation != "acquire" else self.allowed,
                "granted": False if release else self.granted,
                "reason": self.reason
                if operation == "acquire"
                else "concurrency_" + ("released" if release else "renewed"),
                "lease_id": LEASE,
                "retry_after_seconds": 0 if self.allowed else 1,
                "valid_for_ms": 0 if release else self.valid_for,
            },
        )


class ConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_success_owns_work_and_release_payload(self):
        f = LeaseFixture()
        calls = []

        async def work():
            calls.append("model")
            self.assertEqual([x["operation"] for x in f.lease_calls], ["acquire"])
            return "private output"

        async with f.client(concurrency=policy()) as c:
            result = await c.run_concurrent({"private": "context"}, work)
        self.assertTrue(result.allowed and result.leased and result.released)
        self.assertEqual(result.value, "private output")
        self.assertEqual(calls, ["model"])
        self.assertEqual([x["operation"] for x in f.lease_calls], ["acquire", "release"])
        self.assertNotIn("nonce", f.lease_calls[-1])
        self.assertEqual(f.lease_calls[-1]["lease_id"], LEASE)
        self.assertEqual(len(f.lease_calls[0]["subject"]), 64)
        for private in ("private-account", "private output", "context", "x" * 32):
            self.assertNotIn(private, json.dumps(f.lease_calls))

    async def test_observe_exceeded_grant_runs_but_replay_never_does(self):
        for reason, granted in (("concurrency_exceeded", True), ("concurrency_replay", False)):
            f = LeaseFixture()
            f.allowed, f.granted, f.reason = False, granted, reason
            calls = []

            async def work(calls=calls):
                calls.append(True)

            async with f.client(concurrency=policy()) as c:
                r = await c.run_concurrent(None, work)
            self.assertEqual(r.allowed, granted)
            self.assertEqual(len(calls), int(granted))
            self.assertEqual(r.check.decision, "deny")
            if not granted:
                self.assertEqual(r.status, 429)

    async def test_acquire_outage_policy_and_no_retry(self):
        for mode in ("observe", "enforce"):
            for failure in ("open", "closed"):
                f = LeaseFixture()
                f.overrides["acquire"] = 503
                calls = []

                async def work(calls=calls):
                    calls.append(True)

                async with f.client(concurrency=policy(mode=mode, failure_mode=failure)) as c:
                    r = await c.run_concurrent(None, work)
                deny = mode == "enforce" and failure == "closed"
                self.assertEqual(r.allowed, not deny)
                self.assertEqual(len(calls), int(not deny))
                self.assertEqual(len(f.lease_calls), 1)
                self.assertEqual(r.check.decision, "unavailable")

    async def test_malformed_grants_and_expired_grant_never_start_closed_work(self):
        base = {
            "schema": 1,
            "allowed": True,
            "granted": True,
            "reason": "concurrency_allowed",
            "lease_id": LEASE,
            "retry_after_seconds": 0,
            "valid_for_ms": 6000,
        }
        for changes in (
            {"schema": True},
            {"granted": 1},
            {"allowed": 1},
            {"lease_id": "bad"},
            {"valid_for_ms": 6001},
            {"valid_for_ms": 0},
            {"reason": "other"},
            {"allowed": False},
            {"retry_after_seconds": -1},
            {"valid_for_ms": 1},
        ):
            f = LeaseFixture()
            f.overrides["acquire"] = {**base, **changes}

            async def work():
                self.fail("invalid grant started provider")

            async with f.client(concurrency=policy(mode="enforce", failure_mode="closed")) as c:
                r = await c.run_concurrent(None, work)
            self.assertEqual(r.status, 503, changes)
            self.assertEqual(len(f.lease_calls), 1)

    async def test_renewal_runs_and_lease_loss_cancels_work_without_release(self):
        for lost in (False, True):
            f = LeaseFixture()
            f.valid_for = 450
            if lost:
                f.overrides["renew"] = 503
            closed = []

            async def work(lost=lost, f=f, closed=closed):
                try:
                    if lost:
                        await asyncio.sleep(10)
                    else:
                        await f.renewed.wait()
                        await asyncio.sleep(0.01)
                finally:
                    closed.append(True)

            async with f.client(concurrency=policy()) as c:
                if lost:
                    with self.assertRaises(ConcurrencyLeaseLost):
                        await c.run_concurrent(None, work)
                else:
                    r = await c.run_concurrent(None, work)
                    self.assertTrue(r.released)
            self.assertEqual(closed, [True])
            self.assertEqual(any(x["operation"] == "release" for x in f.lease_calls), not lost)

    async def test_cancellation_and_provider_error_retain_reservation(self):
        for cancellation in (False, True):
            f = LeaseFixture()
            entered = asyncio.Event()

            async def work(entered=entered, cancellation=cancellation):
                entered.set()
                if cancellation:
                    await asyncio.sleep(10)
                raise ValueError("private provider error")

            async with f.client(concurrency=policy()) as c:
                task = asyncio.create_task(c.run_concurrent(None, work))
                await entered.wait()
                if cancellation:
                    task.cancel()
                with self.assertRaises(asyncio.CancelledError if cancellation else ValueError):
                    await task
            self.assertEqual([x["operation"] for x in f.lease_calls], ["acquire"])

    async def test_cancel_during_acquire_never_starts_or_releases(self):
        f = LeaseFixture()
        f.acquire_gate = asyncio.Event()

        async def work():
            self.fail("cancelled acquisition started provider")

        async with f.client(concurrency=policy()) as c:
            task = asyncio.create_task(c.run_concurrent(None, work))
            await f.acquiring.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(len(f.lease_calls), 1)

    async def test_release_failure_returns_completed_value_without_retry_error(self):
        f = LeaseFixture()
        f.overrides["release"] = 503

        async def work():
            return "completed"

        async with f.client(concurrency=policy()) as c:
            r = await c.run_concurrent(None, work)
        self.assertEqual(r.value, "completed")
        self.assertTrue(r.leased)
        self.assertFalse(r.released)
        self.assertEqual(len(f.lease_calls), 2)

    async def test_config_limits_and_missing_config(self):
        for changes in (
            {"account_limit": True},
            {"feature_limit": 0},
            {"ttl_seconds": 5},
            {"max_seconds": 901},
            {"timeout": 2},
            {"subject_secret": "short"},
        ):
            with self.assertRaises(ValueError):
                Client(api_key="fixture", property_id=PROPERTY, concurrency=policy(**changes))
        async with LeaseFixture().client() as c:
            with self.assertRaises(ValueError):
                await c.run_concurrent(None, lambda: None)

    async def test_fastapi_stream_background_and_one_combined_report(self):
        f = LeaseFixture()
        f, sent, calls, background, closed = await fastapi_fixture.FastAPITests.exercise(
            self,
            fixture=f,
            concurrency=policy(),
        )
        self.assertEqual(calls, ["handler", "model"])
        self.assertEqual(background, ["ran"])
        self.assertEqual(closed, [True])
        self.assertEqual(len(f.reports), 1)
        self.assertEqual(f.reports[0]["checks"][-1]["id"], "concurrency")
        self.assertEqual(f.reports[0]["action"], "forwarded")
        self.assertEqual(
            [m["body"] for m in sent if m["type"] == "http.response.body"],
            [b"data: first\n\n", b"data: second\n\n", b""],
        )
        self.assertEqual(f.lease_calls[-1]["operation"], "release")

    async def test_fastapi_denial_before_handler(self):
        f = LeaseFixture()
        f.allowed, f.granted, f.reason = False, False, "concurrency_exceeded"
        f, sent, calls, _, _ = await fastapi_fixture.FastAPITests.exercise(
            self, fixture=f, concurrency=policy(mode="enforce")
        )
        self.assertEqual(calls, [])
        self.assertEqual(sent[0]["status"], 429)
        self.assertIn((b"retry-after", b"1"), sent[0]["headers"])
        self.assertEqual(f.reports[0]["action"], "denied")
        self.assertEqual(len(f.lease_calls), 1)

    async def test_fastapi_disconnect_or_error_never_releases(self):
        for opts in (
            {"disconnect": "stream"},
            {"disconnect": "send", "spec": "2.4"},
            {"handler_error": True},
            {"stream_error": True},
        ):
            f = LeaseFixture()
            if opts.get("disconnect") == "stream":
                # Concurrent wrapper deliberately propagates cancellation after the
                # ASGI 2.3 stream returns on disconnect; helper expects normal return.
                with self.assertRaises(asyncio.CancelledError):
                    await fastapi_fixture.FastAPITests.exercise(
                        self, fixture=f, concurrency=policy(), **opts
                    )
            else:
                await fastapi_fixture.FastAPITests.exercise(
                    self, fixture=f, concurrency=policy(), **opts
                )
            self.assertEqual([x["operation"] for x in f.lease_calls], ["acquire"])
            self.assertEqual(len(f.reports), 1)
            self.assertEqual(
                f.reports[0]["action"], "cancelled" if "disconnect" in opts else "handler_error"
            )

    async def test_maximum_runtime_stops_work_even_with_healthy_renewals(self):
        f = LeaseFixture()
        closed = []

        async def work():
            try:
                await asyncio.sleep(20)
            finally:
                closed.append(True)

        async with f.client(concurrency=policy()) as c:
            with self.assertRaises(ConcurrencyLeaseLost):
                await asyncio.wait_for(c.run_concurrent(None, work), 8)
        self.assertEqual(closed, [True])
        self.assertFalse(any(x["operation"] == "release" for x in f.lease_calls))

    async def test_fastapi_renewal_loss_cancels_stream_and_reports_once(self):
        f = LeaseFixture()
        f.valid_for = 120
        f.overrides["renew"] = 503
        with self.assertRaises(ConcurrencyLeaseLost):
            await fastapi_fixture.FastAPITests.exercise(
                self,
                fixture=f,
                concurrency=policy(),
                stream_pause=1,
            )
        self.assertFalse(any(x["operation"] == "release" for x in f.lease_calls))
        self.assertEqual(len(f.reports), 1)
        self.assertEqual(f.reports[0]["action"], "cancelled")

    async def test_fastapi_disconnect_during_handler_creation_retains_lease(self):
        f = LeaseFixture()
        await fastapi_fixture.FastAPITests.exercise(
            self,
            fixture=f,
            concurrency=policy(),
            disconnect="handler",
        )
        self.assertEqual([x["operation"] for x in f.lease_calls], ["acquire"])
        self.assertEqual(f.reports[0]["action"], "cancelled")
