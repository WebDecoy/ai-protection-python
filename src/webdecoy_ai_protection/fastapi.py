"""Route-level FastAPI/Starlette integration; requires the optional fastapi extra."""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response

from .client import Client
from .concurrency import ConcurrencyLeaseLost, _run_concurrent
from .models import Decision, Outcome, RequestMetadata


class _ReportedResponse(Response):
    """Forward the original ASGI response without buffering or replacing its stream."""

    def __init__(self, response: Response, client: Client, decision: Decision, *, report=True):
        self._report = report
        self.outcome = None
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
            self.outcome = Outcome(
                handler_attempted=True,
                status=status,
                cancelled=disconnected or (not finished and not failed),
                handler_error=failed,
            )
            if self._report:
                self._client.report(self._decision, self.outcome)


class _ConcurrentResponse(Response):
    """Acquire before creating the response and own the entire original ASGI stream."""

    def __init__(self, client, decision, handler, context):
        self.client, self.decision = client, decision
        self.handler, self.context = handler, context
        self.status_code, self.raw_headers, self.background = 200, [], None
        self.media_type = None

    async def __call__(self, scope, receive, send):
        attempted = False
        observed = None
        outcome = None

        def admission(result):
            self.decision = self.client._with_concurrency(self.decision, result)

        async def disconnect():
            while True:
                if (await receive())["type"] == "http.disconnect":
                    return

        watcher = asyncio.create_task(disconnect())

        async def work():
            nonlocal attempted, observed
            attempted = True
            response = await self.handler()
            if not isinstance(response, Response):
                raise TypeError("protected handler must return a Starlette response")
            if response.background is None:
                response.background = self.background
            # Transfer receive ownership to the original streaming response.
            if watcher.done() and not watcher.cancelled():
                watcher.result()
                raise asyncio.CancelledError()
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
            observed = _ReportedResponse(response, self.client, self.decision, report=False)
            await observed(scope, receive, send)
            # ASGI 2.3 streams can return normally after a disconnect. That is not
            # confirmation that upstream work completed, and must not release.
            if observed.outcome.cancelled:
                raise asyncio.CancelledError()

        runner = asyncio.create_task(
            _run_concurrent(
                self.client,
                self.client._concurrency,
                self.context,
                work,
                admission,
            )
        )
        try:
            done, _ = await asyncio.wait((watcher, runner), return_when=asyncio.FIRST_COMPLETED)
            if watcher in done and not watcher.cancelled():
                watcher.result()
                raise asyncio.CancelledError()
            result = await runner
            if not result.allowed:
                watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)
                response = JSONResponse(
                    {"error": result.check.reason},
                    status_code=result.status,
                    headers={"Retry-After": str(result.retry_after_seconds)}
                    if result.retry_after_seconds
                    else None,
                )
                response.background = self.background
                await response(scope, receive, send)
                outcome = Outcome(status=result.status)
            elif result.leased and not result.released:
                logging.getLogger("webdecoy_ai_protection").warning(
                    "WebDecoy concurrency release unconfirmed; reservation may remain"
                )
        except (asyncio.CancelledError, ConcurrencyLeaseLost, OSError, ClientDisconnect):
            outcome = Outcome(handler_attempted=attempted, cancelled=True)
            raise
        except Exception:
            outcome = Outcome(handler_attempted=attempted, handler_error=True)
            raise
        finally:
            for task in (watcher, runner):
                if not task.done():
                    task.cancel()
            await asyncio.gather(watcher, runner, return_exceptions=True)
            # The original response records stream failures, including older
            # Starlette ExceptionGroups containing socket failures.
            if observed is not None and observed.outcome is not None:
                outcome = observed.outcome
            self.client.report(self.decision, outcome or Outcome(handler_attempted=attempted))


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
        if client._concurrency is not None:
            return _ConcurrentResponse(client, decision, handler, context)
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
