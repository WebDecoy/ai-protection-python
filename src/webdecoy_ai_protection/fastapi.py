"""Route-level FastAPI/Starlette integration; requires the optional fastapi extra."""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response

from .client import Client
from .models import Decision, Outcome, RequestMetadata


class _ReportedResponse(Response):
    """Forward the original ASGI response without buffering or replacing its stream."""

    def __init__(self, response: Response, client: Client, decision: Decision):
        self._response, self._client, self._decision = response, client, decision
        self.status_code = response.status_code
        self.raw_headers = response.raw_headers
        self.media_type = response.media_type

    @property
    def background(self):
        return self._response.background

    @background.setter
    def background(self, value):
        self._response.background = value

    async def __call__(self, scope, receive, send) -> None:
        disconnected = False
        finished = False
        status = None
        failed = False

        async def receive_original():
            nonlocal disconnected
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
            return message

        async def send_original(message):
            nonlocal status, finished, disconnected
            try:
                await send(message)
            except OSError:
                disconnected = True
                raise
            if message["type"] == "http.response.start":
                status = message["status"]
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                finished = True

        try:
            await self._response(scope, receive_original, send_original)
        except (asyncio.CancelledError, OSError, ClientDisconnect):
            disconnected = True
            raise
        except Exception:
            failed = not disconnected
            raise
        finally:
            # Handler invocation/stream completion is not provider usage or a billing receipt.
            self._client.report(
                self._decision,
                Outcome(
                    handler_attempted=True,
                    status=status,
                    cancelled=disconnected or (not finished and not failed),
                    handler_error=failed,
                ),
            )


async def protect(
    client: Client,
    request: Request,
    handler: Callable[[], Awaitable[Response]],
    *,
    route: str,
    client_ip: str | None,
    context: Any = None,
) -> Response:
    """Call after auth/input validation and after consuming the request body.

    `handler` owns model invocation; do not call it before passing it here. Body
    bytes are never read or sent by this adapter. It monitors disconnect while
    checking admission/creating the response, then the original response handles
    its stream. Callers must supply IP resolution appropriate to their ingress.
    """
    disconnected = asyncio.Event()
    decision: Decision | None = None
    attempted = False
    response_ready = False

    async def watch_disconnect():
        while True:
            message = await request.receive()
            if message["type"] == "http.disconnect":
                disconnected.set()
                return

    async def run():
        nonlocal decision, attempted, response_ready
        decision = await client.check(
            RequestMetadata(
                request.method,
                route,
                client_ip,
                dict(request.headers),
            ),
            context,
        )
        await asyncio.sleep(0)
        if disconnected.is_set():
            raise asyncio.CancelledError()
        if not decision.allowed:
            client.report(decision)
            response_ready = True
            return JSONResponse(
                {"error": decision.reason},
                status_code=decision.status,
                headers={"Retry-After": str(decision.retry_after_seconds)}
                if decision.retry_after_seconds
                else None,
            )
        attempted = True
        response = await handler()
        if not isinstance(response, Response):
            raise TypeError("protected handler must return a Starlette response")
        # The outer coroutine transfers report ownership only when returning to caller.
        return _ReportedResponse(response, client, decision)

    watcher = asyncio.create_task(watch_disconnect())
    work = asyncio.create_task(run())
    try:
        done, _ = await asyncio.wait((watcher, work), return_when=asyncio.FIRST_COMPLETED)
        if watcher in done:
            watcher.result()  # Propagate unexpected receive failures, without invoking inference.
            raise asyncio.CancelledError()
        result = await work
        response_ready = True
        return result
    except asyncio.CancelledError:
        if decision is not None and not response_ready:
            client.report(decision, Outcome(handler_attempted=attempted, cancelled=True))
        raise
    except Exception:
        if decision is not None and not response_ready:
            client.report(decision, Outcome(handler_attempted=attempted, handler_error=True))
        raise
    finally:
        for task in (watcher, work):
            if not task.done():
                task.cancel()
        await asyncio.gather(watcher, work, return_exceptions=True)
