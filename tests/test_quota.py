import asyncio
import json
import unittest
from dataclasses import FrozenInstanceError, replace

import httpx
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse
from test_client import PROPERTY, Fixture

from webdecoy_ai_protection import (
    AccountQuota,
    Client,
    QuotaSubject,
    RequestMetadata,
    Rule,
    RuleResult,
    new_quota_operation_id,
)
from webdecoy_ai_protection.fastapi import protect
from webdecoy_ai_protection.quota import _subject_hash

META = RequestMetadata("POST", "/chat", None)
SECRET = "s" * 32
ACCOUNT = "private-account-\U0001f600"
SESSION = "private-session-\u00e9"


def policy(**kwargs):
    return AccountQuota(
        rule_id="chat_v1",
        subject_secret=SECRET,
        subject=lambda ctx: QuotaSubject(ctx["account"], ctx.get("session", "")),
        limit=2,
        window_seconds=60,
        **kwargs,
    )


class QuotaFixture(Fixture):
    def __init__(self, responses=()):
        super().__init__()
        self.responses = list(responses)
        self.quota_calls = []
        self.entered = asyncio.Event()
        self.quota_gate = None

    async def handle(self, request):
        if not request.url.path.endswith("/quota"):
            return await super().handle(request)
        payload = json.loads(request.content)
        self.quota_calls.append((payload, dict(request.headers)))
        self.entered.set()
        if self.quota_gate:
            await self.quota_gate.wait()
        if self.responses:
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            if isinstance(response, int):
                return httpx.Response(response)
            return httpx.Response(200, json=response)
        return httpx.Response(
            200,
            json={
                "schema": payload["schema"],
                "operation_id": payload.get("operation_id"),
                "allowed": True,
                "reason": "account_quota_allowed",
                "remaining": 1,
                "retry_after_seconds": 0,
                "reset_at": 2000000000,
            },
        )

    def client(self, **kwargs):
        return Client(
            api_key="fixture",
            property_id=PROPERTY,
            transport=httpx.MockTransport(self.handle),
            **kwargs,
        )


DENY = {
    "schema": 1,
    "allowed": False,
    "reason": "account_quota_exceeded",
    "remaining": 0,
    "retry_after_seconds": 30,
    "reset_at": 2000000000,
}
CONTEXT = {"account": ACCOUNT, "session": SESSION}


class QuotaTests(unittest.IsolatedAsyncioTestCase):
    async def test_policy_matrix_independent_of_detector_and_dashboard(self):
        for mode in ("observe", "enforce"):
            for failure in ("open", "closed"):
                for outage in (False, True):
                    with self.subTest(mode=mode, failure=failure, outage=outage):
                        f = QuotaFixture([503 if outage else DENY])
                        async with f.client(
                            account_quota=policy(mode=mode, failure_mode=failure)
                        ) as c:
                            d = await c.check(META, CONTEXT)
                            deny = mode == "enforce" and (not outage or failure == "closed")
                            self.assertEqual(d.allowed, not deny)
                            self.assertEqual(d.status, (503 if outage else 429) if deny else 0)
                            self.assertEqual(
                                d.retry_after_seconds, 30 if deny and not outage else 0
                            )
                            self.assertEqual(
                                d.quota.check.decision, "unavailable" if outage else "deny"
                            )
                            c.report(d)
                            await c.flush()
                        self.assertEqual(len(f.quota_calls), 1)
                        self.assertEqual(
                            f.reports[0]["action"],
                            "denied_unavailable"
                            if deny and outage
                            else "denied"
                            if deny
                            else "forwarded",
                        )

    async def test_wire_subjects_match_cross_language_framing_and_keep_ids_private(self):
        f = QuotaFixture()
        q = policy(session_limit=1, idempotency=True)
        async with f.client(account_quota=q) as c:
            d = await c.check(META, CONTEXT)
            self.assertTrue(d.allowed)
            self.assertEqual(d.quota.remaining, 1)
            with self.assertRaises(FrozenInstanceError):
                q.limit = 9
            c.report(d)
            await c.flush()
        payload, headers = f.quota_calls[0]
        self.assertEqual(payload["schema"], 2)
        self.assertEqual(
            payload["subject"], "6df8eedd4a59f4dae762e4f728c8ee9ca05bae8ac3a815eb3166ce5037383566"
        )
        self.assertEqual(
            payload["session"], "63f79ba26bd6c2d69b2bfd34c112b32a99a4d618abfea3822e9838b42776e14c"
        )
        self.assertEqual(headers["x-webdecoy-property-id"], PROPERTY)
        self.assertEqual(payload["operation_id"], d.quota.operation_id)
        all_payloads = json.dumps([payload, *f.reports], ensure_ascii=False)
        for secret in (ACCOUNT, SESSION, SECRET):
            self.assertNotIn(secret, all_payloads)
            self.assertNotIn(secret, repr(q))
        self.assertNotIn(d.quota.operation_id, json.dumps(f.reports))
        self.assertNotEqual(_subject_hash(SECRET, "ab", "c"), _subject_hash(SECRET, "a", "bc"))

    async def test_local_denial_never_consumes_shared_quota(self):
        f = QuotaFixture()
        async with f.client(
            account_quota=policy(),
            rules=[
                Rule("plan", lambda _: RuleResult(False), mode="enforce"),
            ],
        ) as c:
            d = await c.check(META, CONTEXT)
        self.assertFalse(d.allowed)
        self.assertIsNone(d.quota)
        self.assertEqual(f.quota_calls, [])

    async def test_idempotent_recovery_keeps_payload_and_operation(self):
        for first in (503, httpx.ReadError("lost response"), {"schema": 2}):
            f = QuotaFixture([first])
            op = new_quota_operation_id()
            async with f.client(
                account_quota=policy(idempotency=True, operation_id=lambda _, op=op: op)
            ) as c:
                d = await c.check(META, CONTEXT)
            self.assertTrue(d.allowed)
            self.assertEqual(len(f.quota_calls), 2)
            self.assertEqual(f.quota_calls[0][0], f.quota_calls[1][0])
            self.assertEqual(d.quota.operation_id, op)
            self.assertEqual(d.quota.check.decision, "allow")

    async def test_terminal_errors_do_not_retry_and_uncertainty_survives_expiry(self):
        for statuses in ([400], [401], [403], [409], [410], [429], [302], [503, 503], [503, 410]):
            with self.subTest(statuses=statuses):
                f = QuotaFixture(statuses)
                async with f.client(
                    account_quota=policy(
                        mode="enforce",
                        failure_mode="closed",
                        idempotency=True,
                    )
                ) as c:
                    d = await c.check(META, CONTEXT)
                self.assertFalse(d.allowed)
                self.assertEqual(d.status, 503)
                self.assertEqual(len(f.quota_calls), len(statuses))
                self.assertEqual(
                    d.reason,
                    "account_quota_outcome_unknown"
                    if statuses[0] == 503
                    else "account_quota_unavailable",
                )
        f = QuotaFixture([503])
        async with f.client(account_quota=policy()) as c:
            d = await c.check(META, CONTEXT)
        self.assertEqual(len(f.quota_calls), 1)
        self.assertEqual(d.quota.check.reason, "account_quota_unavailable")

    async def test_invalid_responses_never_grant_enforced_admission(self):
        for changes in (
            {"schema": True},
            {"schema": 2},
            {"allowed": 1},
            {"remaining": -1},
            {"remaining": 3},
            {"remaining": True},
            {"reset_at": True},
            {"reset_at": 0},
            {"retry_after_seconds": 0},
            {"retry_after_seconds": 61},
            {"reason": "other"},
            {"allowed": True},
        ):
            f = QuotaFixture([{**DENY, **changes}])
            async with f.client(account_quota=policy(mode="enforce", failure_mode="closed")) as c:
                d = await c.check(META, CONTEXT)
            self.assertFalse(d.allowed, changes)
            self.assertEqual(d.status, 503, changes)
        op = new_quota_operation_id()
        f = QuotaFixture([{**DENY, "schema": 2, "operation_id": op}] * 2)
        async with f.client(
            account_quota=policy(
                mode="enforce",
                failure_mode="closed",
                idempotency=True,
            )
        ) as c:
            d = await c.check(META, CONTEXT)
        self.assertEqual(d.reason, "account_quota_outcome_unknown")

    async def test_invalid_subjects_callbacks_and_ids_cannot_reach_service(self):
        async def asynchronous(_):
            return QuotaSubject(ACCOUNT)

        def failing(_):
            raise RuntimeError("private callback secret")

        for subject in (
            lambda _: QuotaSubject(""),
            lambda _: QuotaSubject("\ud800"),
            lambda _: QuotaSubject("\U0001f600" * 65),
            lambda _: QuotaSubject(ACCOUNT, ""),
            lambda _: asynchronous(None),
            failing,
        ):
            f = QuotaFixture()
            q = replace(
                policy(session_limit=1, mode="enforce", failure_mode="closed"), subject=subject
            )
            async with f.client(account_quota=q) as c:
                d = await c.check(META, CONTEXT)
            self.assertFalse(d.allowed)
            self.assertEqual(f.quota_calls, [])
        for value in ("bad", "private-secret", None):
            f = QuotaFixture()
            q = policy(
                idempotency=True,
                operation_id=lambda _, value=value: value,
                mode="enforce",
                failure_mode="closed",
            )
            async with f.client(account_quota=q) as c:
                d = await c.check(META, CONTEXT)
            self.assertEqual(f.quota_calls, [])
            self.assertIsNone(d.quota.operation_id)

    async def test_timeout_is_bounded_and_caller_cancellation_never_retries(self):
        f = QuotaFixture()
        f.quota_gate = asyncio.Event()
        async with f.client(account_quota=policy(timeout=0.01, idempotency=True)) as c:
            d = await asyncio.wait_for(c.check(META, CONTEXT), 0.5)
            self.assertTrue(d.allowed)
            self.assertEqual(d.quota.check.reason, "account_quota_outcome_unknown")
            self.assertEqual(len(f.quota_calls), 2)
        f = QuotaFixture()
        f.quota_gate = asyncio.Event()
        async with f.client(account_quota=policy(idempotency=True)) as c:
            task = asyncio.create_task(c.check(META, CONTEXT))
            await f.entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(len(f.quota_calls), 1)

    async def test_invalid_configuration(self):
        async def callback(_):
            return QuotaSubject("account")

        for changes in (
            {"subject_secret": "short"},
            {"subject_secret": "\ud800" * 32},
            {"limit": True},
            {"limit": 0},
            {"limit": 1000001},
            {"window_seconds": 86401},
            {"session_limit": 3},
            {"rule_id": "Invalid"},
            {"mode": "bad"},
            {"failure_mode": "bad"},
            {"timeout": float("nan")},
            {"idempotency": 1},
            {"operation_id": lambda _: "x"},
            {"subject": callback},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                Client(
                    api_key="key", property_id=PROPERTY, account_quota=replace(policy(), **changes)
                )

    async def test_fastapi_denial_exposes_retry_after_before_handler(self):
        f = QuotaFixture([DENY])
        calls = []
        async with f.client(account_quota=policy(mode="enforce")) as client:
            app = FastAPI()

            @app.post("/chat")
            async def route(request: Request):
                await request.body()

                async def handler():
                    calls.append(True)
                    return JSONResponse({"result": "expensive"})

                return await protect(
                    client, request, handler, route="/chat", client_ip=None, context=CONTEXT
                )

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as caller:
                response = await caller.post("/chat", json={"prompt": "private"})
            await client.flush()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["retry-after"], "30")
        self.assertEqual(calls, [])
        self.assertEqual(f.reports[0]["checks"][0]["source"], "shared")
