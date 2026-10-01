"""Local deterministic chat fixture: no paid model or production identity store."""

import asyncio
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.responses import StreamingResponse

from webdecoy_ai_protection import Client, Rule, RuleResult
from webdecoy_ai_protection.fastapi import protect
from webdecoy_ai_protection.ingress import resolve_client_ip


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        if not os.environ.get("EXAMPLE_TOKEN"):
            raise RuntimeError("EXAMPLE_TOKEN required for local fixture")
        async with Client(
            api_key=os.environ["WEBDECOY_KEY"],
            property_id=os.environ["WEBDECOY_PROPERTY_ID"],
            base_url=os.environ.get("WEBDECOY_URL", "https://ai-protection.webdecoy.com"),
            rules=[
                Rule(
                    "input_limit",
                    lambda ctx: RuleResult(ctx["length"] <= 1000, "input_limit"),
                    mode="enforce",
                )
            ],
        ) as client:
            app.state.protection = client
            yield

    app = FastAPI(lifespan=lifespan)

    class Chat(BaseModel):
        prompt: str = Field(min_length=1, max_length=4000)

    @app.post("/chat")
    async def chat(request: Request, data: Chat):
        if not secrets.compare_digest(
            request.headers.get("authorization", ""), "Bearer " + os.environ["EXAMPLE_TOKEN"]
        ):
            raise HTTPException(401, "unauthorized")
        if not data.prompt.strip():
            raise HTTPException(400, "empty prompt")
        # Direct loopback example; use uvicorn --no-proxy-headers. Real ingress
        # needs explicit CIDRs and an original, unmodified socket peer.
        ip = resolve_client_ip(request.client.host if request.client else None, request.headers)

        async def handler():
            async def model():
                for text in ("Local ", "model ", "fixture"):
                    await asyncio.sleep(0.02)
                    yield "data: " + text + "\n\n"

            return StreamingResponse(model(), media_type="text/event-stream")

        return await protect(
            app.state.protection,
            request,
            handler,
            route="/chat",
            client_ip=ip,
            context={"length": len(data.prompt)},
        )

    return app
