import asyncio
import json
import time
import unittest
from dataclasses import FrozenInstanceError, replace

import httpx

from webdecoy_ai_protection import Client, Outcome, RequestMetadata, Rule, RuleResult
from webdecoy_ai_protection.ingress import resolve_client_ip

PROPERTY = "11111111-1111-4111-8111-111111111111"
ORG = "22222222-2222-4222-8222-222222222222"
META = RequestMetadata(
    "POST",
    "/chat/{conversation}",
    "192.0.2.1",
    {
        "Authorization": "Bearer private-auth",
        "Cookie": "session=private-cookie",
        "User-Agent": "fixture",
        "Accept-Language": "en",
        "X-Private": "private-header",
    },
)


class Fixture:
    def __init__(self):
        self.calls = []
        self.binding = {
            "schema": 1,
            "property_id": PROPERTY,
            "organization_id": ORG,
            "mode": "enforce",
            "observe": True,
            "enforce": True,
        }
        self.verdict = "allow"
        self.detect_error = False
        self.config_status = 200
        self.gate = None
        self.report_gate = None

    async def handle(self, request):
        self.calls.append(
            (request.url.path, json.loads(request.content or b"{}"), dict(request.headers))
        )
        if request.url.path.endswith("/config"):
            if self.gate:
                await self.gate.wait()
            return httpx.Response(self.config_status, json=self.binding)
        if request.url.path.endswith("/reports"):
            if self.report_gate:
                await self.report_gate.wait()
            return httpx.Response(202, json={"accepted": True})
        if self.detect_error:
            raise httpx.ConnectError("fixture secret must not be logged")
        return httpx.Response(200, json={"decision_mode": "unified_v1", "decision": self.verdict})

    def client(self, **kwargs):
        return Client(
            api_key="fixture-key",
            property_id=PROPERTY,
            transport=httpx.MockTransport(self.handle),
            **kwargs,
        )

    @property
    def reports(self):
        return [payload for path, payload, _ in self.calls if path.endswith("/reports")]


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_wire_privacy_and_immutable_owned_once_reports(self):
        f = Fixture()
        async with f.client() as client, f.client() as foreign:
            d = await client.check(META, {"private-context": "private-secret"})
            self.assertTrue(d.allowed)
            self.assertFalse(d.degraded)
            with self.assertRaises(FrozenInstanceError):
                d.allowed = False
            self.assertFalse(foreign.report(d))
            self.assertFalse(client.report(replace(d)))
            self.assertTrue(client.report(d, Outcome(handler_attempted=True, status=200)))
            self.assertFalse(client.report(d))
            await client.flush()
        wire = json.dumps([payload for _, payload, _ in f.calls])
        for secret in [
            "private-auth",
            "private-cookie",
            "private-header",
            "private-secret",
            "private-context",
        ]:
            self.assertNotIn(secret, wire)
        self.assertEqual(f.reports[0]["checks"][-1]["reason"], "detector_allow")
        self.assertNotIn("192.0.2.1", json.dumps(f.reports))
        self.assertEqual(f.reports[0]["request_id"], d.id)
        for _, _, headers in f.calls:
            self.assertEqual(headers["x-webdecoy-property-id"], PROPERTY)

    async def test_enforcement_observation_and_failure_matrix(self):
        for mode, cloud_mode, permitted, verdict, error, failure, allowed, degraded, status in [
            ("observe", "enforce", True, "block", False, "open", True, False, 0),
            ("enforce", "observe", True, "block", False, "open", True, False, 0),
            ("enforce", "enforce", False, "block", False, "open", True, False, 0),
            ("enforce", "enforce", True, "block", False, "open", False, False, 403),
            ("enforce", "enforce", True, "challenge", False, "open", False, False, 403),
            ("enforce", "enforce", True, "allow", True, "open", True, True, 0),
            ("enforce", "enforce", True, "allow", True, "closed", False, True, 503),
        ]:
            with self.subTest(
                mode=mode, cloud=cloud_mode, verdict=verdict, error=error, failure=failure
            ):
                f = Fixture()
                f.binding.update(mode=cloud_mode, enforce=permitted)
                f.verdict, f.detect_error = verdict, error
                async with f.client(mode=mode, detector_failure_mode=failure) as client:
                    d = await client.check(META)
                    self.assertEqual((d.allowed, d.degraded, d.status), (allowed, degraded, status))

    async def test_bad_binding_cannot_authorize_or_score(self):
        for update in [
            {"property_id": ORG},
            {"schema": True},
            {"mode": []},
            {"enforce": 1},
            {"organization_id": "bad"},
            {"observe": False},
        ]:
            f = Fixture()
            f.binding.update(update)
            async with f.client(mode="enforce", detector_failure_mode="closed") as client:
                d = await client.check(META)
                self.assertTrue(d.allowed)
                self.assertTrue(d.degraded)
                self.assertEqual(len(f.calls), 1)
                self.assertEqual(d.checks[-1].mode, "observe")

    async def test_cached_binding_expiry_and_failed_refresh(self):
        f = Fixture()
        async with f.client(mode="enforce") as client:
            await client.check(META)
            await client.check(META)
            self.assertEqual(sum(p.endswith("/config") for p, _, _ in f.calls), 1)
            f.config_status = 401
            client._until = 0
            d = await client.check(META)
            self.assertTrue(d.degraded)
            self.assertEqual(d.checks[-1].mode, "observe")
            count = len(f.calls)
            await client.check(META)
            self.assertEqual(len(f.calls), count)  # Failure cached; no stale scoring grant.

    async def test_rules_deny_before_remote_and_observed_errors_visible(self):
        f = Fixture()
        async with f.client(
            rules=[Rule("plan", lambda c: RuleResult(c["paid"], "paid_required"), mode="enforce")]
        ) as client:
            d = await client.check(META, {"paid": False})
            self.assertFalse(d.allowed)
            self.assertEqual(d.reason, "paid_required")
            self.assertEqual(f.calls, [])
            client.report(d)
            await client.flush()
            self.assertEqual(f.reports[0]["action"], "denied")

        async def bad(_):
            return RuleResult(True)

        for mode, failure, allowed in [
            ("observe", "closed", True),
            ("enforce", "closed", False),
            ("enforce", "open", True),
        ]:
            async with f.client(rules=[Rule("bad", lambda _: bad(None), mode, failure)]) as client:
                d = await client.check(META)
                self.assertEqual(d.allowed, allowed)
                self.assertTrue(d.degraded)
                self.assertEqual(d.checks[0].reason, "local_rule_error")

    async def test_cancellation_does_not_poison_shared_binding(self):
        f = Fixture()
        f.gate = asyncio.Event()
        async with f.client() as client:
            first = asyncio.create_task(client.check(META))
            second = asyncio.create_task(client.check(META))
            await asyncio.sleep(0.01)
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
            f.gate.set()
            self.assertTrue((await second).allowed)
            self.assertEqual(sum(p.endswith("/config") for p, _, _ in f.calls), 1)
            self.assertEqual(sum(p.endswith("/detect") for p, _, _ in f.calls), 1)

    async def test_queue_is_bounded_duplicate_drops_not_retried_and_failure_isolated(self):
        f = Fixture()
        f.report_gate = asyncio.Event()
        async with f.client(max_pending_reports=1, reporting_timeout=0.03) as client:
            first, second = await client.check(META), await client.check(META)
            self.assertTrue(client.report(first))
            self.assertFalse(client.report(second))
            start = time.monotonic()
            await client.flush()
            self.assertLess(time.monotonic() - start, 0.3)
            self.assertFalse(client.report(second))
            third = await client.check(META)
            self.assertTrue(client.report(third))
            f.report_gate.set()
            await client.flush()

    async def test_missing_ip_and_metadata_validation(self):
        f = Fixture()
        async with f.client() as client:
            for ip in [None, "bad", "fe80::1%eth0", 123]:
                d = await client.check(replace(META, client_ip=ip))
                self.assertTrue(d.allowed and d.degraded)
            self.assertEqual(f.calls, [])
            for route in ["/chat?secret=x", "/chat#id", "bad", "/" + "x" * 512]:
                with self.assertRaises(ValueError):
                    await client.check(replace(META, route=route))

    async def test_remote_redirect_size_protocol_compression_and_timeout(self):
        f = Fixture()
        cases = [
            httpx.Response(302, headers={"location": "https://outside.invalid/leak"}),
            httpx.Response(200, content=b"x" * 65537),
            httpx.Response(200, content=b"not json"),
            httpx.Response(200, json={"decision": "allow"}),
            httpx.Response(200, content=b"{}", headers={"content-encoding": "br"}),
        ]
        for response in cases:

            async def transport(request, response=response):
                if request.url.path.endswith("/config"):
                    return await f.handle(request)
                return response

            async with Client(
                api_key="key", property_id=PROPERTY, transport=httpx.MockTransport(transport)
            ) as client:
                d = await client.check(META)
                self.assertTrue(d.allowed and d.degraded)

        async def slow(request):
            if request.url.path.endswith("/config"):
                return await f.handle(request)
            await asyncio.sleep(5)

        async with Client(
            api_key="key",
            property_id=PROPERTY,
            detector_timeout=0.025,
            transport=httpx.MockTransport(slow),
        ) as client:
            start = time.monotonic()
            d = await client.check(META)
            self.assertTrue(d.allowed and d.degraded)
            self.assertLess(time.monotonic() - start, 0.3)

    async def test_closed_client_guard(self):
        f = Fixture()
        client = f.client()
        await client.aclose()
        await client.aclose()
        with self.assertRaises(RuntimeError):
            await client.check(META)

    def test_configuration_and_trusted_ingress(self):
        for option in [
            {"base_url": "http://remote.invalid"},
            {"base_url": "https://user@x.invalid"},
            {"base_url": "https://x.invalid/path"},
            {"base_url": "https://x.invalid?"},
            {"detector_timeout": float("nan")},
            {"max_pending_reports": True},
            {"rules": [Rule("webdecoy", lambda _: RuleResult(True))]},
        ]:
            with self.assertRaises(ValueError):
                Fixture().client(**option)
        self.assertIsNone(resolve_client_ip("192.0.2.5", {"X-Forwarded-For": "203.0.113.1"}))
        self.assertEqual(
            resolve_client_ip(
                "127.0.0.1",
                {"X-Forwarded-For": "spoof, 192.0.2.8"},
                trusted_proxy_cidrs=["127.0.0.1/32"],
            ),
            "192.0.2.8",
        )
        self.assertIsNone(
            resolve_client_ip(
                "127.0.0.1", {"X-Forwarded-For": "bad"}, trusted_proxy_cidrs=["127.0.0.1/32"]
            )
        )
        with self.assertRaises(ValueError):
            resolve_client_ip("127.0.0.1", {}, trusted_proxy_cidrs=["0.0.0.0/0"])
