"""One non-streaming local Ollama attempt, after application auth/admission."""

import asyncio
import os

from ollama import AsyncClient

from webdecoy_ai_protection import (
    Budget,
    BudgetCall,
    BudgetCompletion,
    BudgetLimits,
    BudgetPrice,
    BudgetSubject,
    Client,
    ollama_budget_usage,
)

MODEL = "qwen2.5:0.5b"
CONTEXT_TOKENS = 2048
OUTPUT_TOKENS = 128


async def generate(protection, provider, trusted_context, prompt, request_id=None):
    """Preserve output and accounting status; do not retry on accounting failure."""
    if not isinstance(prompt, str) or not 1 <= len(prompt.encode("utf-8")) <= 1024:
        raise ValueError("prompt must contain 1–1024 UTF-8 bytes")

    async def attempt(runtime):
        if runtime.provider != "ollama" or runtime.model != MODEL:
            raise ValueError("example requires the configured local model")
        # Raw generation excludes model templates/history/tools. Reserve the
        # entire configured input context, not a character-based token estimate.
        response = await provider.generate(
            model=runtime.model,
            prompt=prompt,
            raw=True,
            stream=False,
            options={"num_ctx": runtime.max_input_tokens, "num_predict": runtime.max_output_tokens},
        )
        usage = ollama_budget_usage(
            response.model, response.done, response.prompt_eval_count, response.eval_count
        )
        return BudgetCompletion(response.response, usage)

    return await protection.run_budget(
        trusted_context,
        BudgetCall("local", CONTEXT_TOKENS, OUTPUT_TOKENS, request_id),
        attempt,
    )


async def main():
    budget = Budget(
        rule_id="ollama_example_v1",
        subject_secret=os.environ["WEBDECOY_SUBJECT_SECRET"],
        subject=lambda ctx: BudgetSubject(ctx["account_id"], ctx["organization_id"]),
        window_seconds=3600,
        limits=BudgetLimits(account_tokens=100_000),
        prices={"local": BudgetPrice("ollama", MODEL, 0, 0)},
        mode="observe",
        failure_mode="open",
    )
    # Explicit loopback host and local model: no paid-provider fallback.
    provider = AsyncClient(host="http://127.0.0.1:11434", timeout=60, trust_env=False)
    async with Client(
        api_key=os.environ["WEBDECOY_KEY"],
        property_id=os.environ["WEBDECOY_PROPERTY_ID"],
        budget=budget,
    ) as protection:
        result = await generate(
            protection,
            provider,
            {"account_id": "local-demo", "organization_id": "local-demo"},
            "Say hello in one short sentence.",
        )
        print(result.reason)
        if result.allowed:
            print(result.value)
        else:
            print(f"Denied: HTTP {result.status}; retry after {result.retry_after_seconds}s")


if __name__ == "__main__":
    asyncio.run(main())
