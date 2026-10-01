import asyncio
import json
import unittest

from fastapi import BackgroundTasks, FastAPI, Request
from starlette.requests import ClientDisconnect
from starlette.responses import StreamingResponse
from test_client import Fixture

from webdecoy_ai_protection import Rule, RuleResult
from webdecoy_ai_protection.fastapi import protect


class FastAPITests(unittest.IsolatedAsyncioTestCase):
    async def exercise(
        self,
        *,
        verdict="allow",
        outage=False,
        local_deny=False,
        disconnect=None,
        handler_error=False,
        stream_error=False,
        spec="2.3",
    ):
        fixture = Fixture()
        fixture.verdict = verdict
        fixture.detect_error = outage
        if disconnect == "admission":
            fixture.gate = asyncio.Event()
        incoming = asyncio.Queue()
        prompt = "private prompt; never send to WebDecoy"
        await incoming.put(
            {
                "type": "http.request",
                "body": json.dumps({"prompt": prompt}).encode(),
                "more_body": False,
            }
        )
        sent, calls, backgrounds, closed = [], [], [], []
        client = fixture.client(
            mode="enforce",
            rules=[Rule("plan", lambda _: RuleResult(not local_deny), mode="enforce")],
        )
        app = FastAPI()

        @app.post("/chat")
        async def chat(request: Request, background_tasks: BackgroundTasks):
            data = await request.json()  # Existing validation/body consumption precedes admission.
            self.assertEqual(data["prompt"], prompt)
            self.assertEqual(request.headers["authorization"], "Bearer private-auth")
            background_tasks.add_task(backgrounds.append, "ran")

            async def handler():
                calls.append("handler")
                if disconnect == "handler":
                    await incoming.put({"type": "http.disconnect"})
                    await asyncio.sleep(10)
                if handler_error:
                    raise ValueError("private model error")

                async def stream():
                    try:
                        calls.append("model")
                        yield b"data: first\n\n"
                        await asyncio.sleep(0.01)
                        if stream_error:
                            raise ValueError("private stream error")
                        yield b"data: second\n\n"
                    finally:
                        closed.append(True)

                return StreamingResponse(
                    stream(), media_type="text/event-stream", headers={"x-test-stream": "preserved"}
                )

            return await protect(
                client,
                request,
                handler,
                route="/chat",
                client_ip="192.0.2.9",
                context={"server-identity": "private-user"},
            )

        async def send(message):
            if disconnect == "send" and message["type"] == "http.response.body":
                raise OSError("socket closed")
            sent.append(message)
            if (
                disconnect == "stream"
                and message["type"] == "http.response.body"
                and message.get("body")
            ):
                await incoming.put({"type": "http.disconnect"})

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": spec},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/chat",
            "raw_path": b"/chat",
            "query_string": b"",
            "root_path": "",
            "headers": [
                (b"content-type", b"application/json"),
                (b"authorization", b"Bearer private-auth"),
            ],
            "server": ("localhost", 8092),
            "client": ("192.0.2.9", 1234),
        }
        async with client:
            task = asyncio.create_task(app(scope, incoming.get, send))
            if disconnect == "admission":
                for _ in range(100):
                    if fixture.calls:
                        break
                    await asyncio.sleep(0.001)
                await incoming.put({"type": "http.disconnect"})
            if disconnect in ("admission", "handler"):
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 1)
            elif disconnect == "send":
                with self.assertRaises((ClientDisconnect, OSError, ExceptionGroup)) as caught:
                    await asyncio.wait_for(task, 1)
            elif handler_error or stream_error:
                with self.assertRaises((ValueError, ExceptionGroup)) as caught:
                    await asyncio.wait_for(task, 1)
            else:
                await asyncio.wait_for(task, 1)
            if disconnect == "send" or handler_error or stream_error:
                expected = (ClientDisconnect, OSError) if disconnect == "send" else (ValueError,)

                def check_error(error):
                    if isinstance(error, ExceptionGroup):
                        for child in error.exceptions:
                            check_error(child)
                    else:
                        self.assertIsInstance(error, expected)

                check_error(caught.exception)
            await client.flush()
        payloads = json.dumps([value for _, value, _ in fixture.calls])
        for secret in [
            prompt,
            "private-auth",
            "private-user",
            "private model error",
            "private stream error",
        ]:
            self.assertNotIn(secret, payloads)
        return fixture, sent, calls, backgrounds, closed

    async def test_original_stream_and_fastapi_background_preserved(self):
        f, sent, calls, backgrounds, closed = await self.exercise()
        self.assertEqual(calls, ["handler", "model"])
        self.assertEqual(backgrounds, ["ran"])
        self.assertEqual(closed, [True])
        chunks = [m["body"] for m in sent if m["type"] == "http.response.body"]
        self.assertEqual(chunks, [b"data: first\n\n", b"data: second\n\n", b""])
        self.assertIn((b"x-test-stream", b"preserved"), sent[0]["headers"])
        self.assertEqual(f.reports[0]["action"], "forwarded")
        self.assertEqual(f.reports[0]["handler_status"], 200)

    async def test_deny_before_inference_local_and_cloud(self):
        for opts in [{"local_deny": True}, {"verdict": "block"}, {"verdict": "challenge"}]:
            f, sent, calls, _, _ = await self.exercise(**opts)
            self.assertEqual(calls, [])
            self.assertEqual(sent[0]["status"], 403)
            self.assertFalse(f.reports[0]["handler_attempted"])
            if opts.get("local_deny"):
                self.assertEqual(len(f.calls), 1)  # Report only; no detector/config calls.

    async def test_outage_preserves_inference_and_marks_degraded(self):
        f, sent, calls, _, _ = await self.exercise(outage=True)
        self.assertEqual(sent[0]["status"], 200)
        self.assertEqual(calls, ["handler", "model"])
        self.assertTrue(f.reports[0]["degraded"])

    async def test_disconnect_during_admission_never_invokes_handler(self):
        f, _, calls, _, _ = await self.exercise(disconnect="admission")
        self.assertEqual(calls, [])
        self.assertFalse(any(path.endswith("/detect") for path, _, _ in f.calls))

    async def test_disconnect_cancels_handler_creation(self):
        f, _, calls, _, _ = await self.exercise(disconnect="handler")
        self.assertEqual(calls, ["handler"])
        self.assertEqual(f.reports[0]["action"], "cancelled")

    async def test_disconnect_closes_stream_and_reports_cancelled(self):
        f, _, _, _, closed = await self.exercise(disconnect="stream")
        self.assertEqual(closed, [True])
        self.assertEqual(f.reports[0]["action"], "cancelled")

    async def test_handler_and_stream_exceptions_report_once(self):
        for opts in [{"handler_error": True}, {"stream_error": True}]:
            f, _, _, _, _ = await self.exercise(**opts)
            self.assertEqual(len(f.reports), 1)
            self.assertEqual(f.reports[0]["action"], "handler_error")

    async def test_asgi_24_socket_failure_reports_cancelled(self):
        f, _, calls, _, _ = await self.exercise(disconnect="send", spec="2.4")
        self.assertEqual(calls, ["handler", "model"])
        self.assertEqual(len(f.reports), 1)
        self.assertEqual(f.reports[0]["action"], "cancelled")
