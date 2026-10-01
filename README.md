# WebDecoy AI Protection for Python

Async request admission for Python AI endpoints. Local application rules run in
your process; bot detection runs in WebDecoy. Apache-2.0 licensed.

**Development preview, not published to PyPI.** This first implementation covers
admission, reporting and an explicit FastAPI/Starlette route wrapper. Shared quota,
concurrency, model-budget accounting, browser evidence and MCP adapters are not yet
implemented. It is not a prompt-injection filter or a spending guarantee.

## Local installation

Requires Python 3.11+ and asyncio. HTTPX is the only core runtime dependency.
FastAPI/Starlette support is optional; synchronous applications and Trio are not
supported in this preview. From this checkout:

```sh
python -m pip install '.[fastapi]'
```

## Core client

```python
from webdecoy_ai_protection import Client, RequestMetadata, Outcome

async with Client(api_key=server_key, property_id=property_id) as client:
    decision = await client.check(RequestMetadata(
        method="POST", route="/api/chat", client_ip=trusted_client_ip,
    ))
    if not decision.allowed:
        # Return decision.status / decision.reason before starting your model.
        ...
    else:
        # Authenticate/authorize/validate before check; invoke your model here.
        ...
    client.report(decision, Outcome(handler_attempted=decision.allowed))
    await client.flush()
```

In a server, create one client in application lifespan and reuse it across requests.
The base URL defaults to `https://ai-protection.webdecoy.com`. Use a server-only
API key scoped to your property with Write Detections permission. View decisions
at https://app.webdecoy.com/ai-protection. Never put that key in browser code.

`check()` returns an immutable decision. Callers must enforce it; it is not an
authentication grant. A caller must not start inference after cancellation.
`report()` queues at most one outcome per decision issued by that client and does
not wait for network delivery. `flush()` drains the current queue; `aclose()`
drains and closes HTTP resources. Drain application handlers before shutdown.

## FastAPI integration

See `examples/fastapi_app.py`. It uses a deterministic local response and no paid
model credentials. Run Uvicorn with `--no-proxy-headers` for that direct-loopback
example so the original socket peer remains available. The example's bearer token
is a local test fixture, not a production identity or entitlement system.

Run from the checkout after setting your server credentials:

```sh
python -m pip install -e '.[dev]'
export WEBDECOY_KEY='your-server-key'
export WEBDECOY_PROPERTY_ID='your-property-uuid'
export EXAMPLE_TOKEN='choose-a-local-test-token'
uvicorn examples.fastapi_app:create_app --factory --no-proxy-headers --host 127.0.0.1 --port 8092
```

In another shell with the same `EXAMPLE_TOKEN`:

```sh
curl -N http://127.0.0.1:8092/chat \
  -H "Authorization: Bearer $EXAMPLE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"prompt":"hello"}'
```

Call `webdecoy_ai_protection.fastapi.protect` inside an authenticated route, after
input validation and request-body consumption. Pass a deferred async handler that
returns the original Starlette `Response`. The adapter monitors disconnect during
admission/response creation and forwards the original ASGI stream unchanged. It
reports response completion/error/disconnect without buffering model output.
Handlers and model generators must cooperate with cancellation. A cancelled task
is not proof the remote provider stopped or refunded work.

Use `ingress.resolve_client_ip` only with an **original socket peer** and explicitly
configured trusted proxy CIDRs. Your ingress must append/overwrite forwarding
headers and prevent bypass. Do not use a peer already rewritten by framework proxy
middleware. Missing/untrusted IP evidence skips scoring and marks coverage degraded.
Routes are fixed templates, not real user IDs or raw request URLs.

## Policies and availability

`Rule(id, evaluate, mode="observe", failure_mode="closed")` accepts a cheap,
synchronous function returning `RuleResult`. The context must come from your
server's authenticated state. Never accept a browser's entitlement/plan claim.
Rules cannot perform network I/O. Coroutine results are rejected as rule errors.

- Cloud mode defaults to `observe`; use `mode="enforce"` only after review. Remote
  denial enforces only when the verified account configuration also allows it.
- Detector failure defaults to `open`: continue with degraded coverage. Explicit
  `detector_failure_mode="closed"` denies an unavailable detector in effective
  enforcement mode. Unavailable/mismatched account bindings skip scoring in observe.
- Enforced local denials apply even when the detector is unavailable. Enforced
  local rule errors default to 503; each rule may explicitly choose fail-open.
- Reporting failures never change the application response. Delivery is bounded,
  best effort, with no retry or durable queue. Queue-full reports are dropped.
- Cancellation propagates; it is never converted to an allow decision.

Each config lookup and detector call has a one-second default deadline (maximum
10s each). Cold admission can therefore add approximately two seconds of configured
network waiting; verified config caches for 60s, failed bindings for 5s. This is
not an end-to-end latency SLA. Reporting defaults to a separate one-second deadline
and 100 pending tasks. Remote JSON responses are capped at 64KiB; outgoing JSON at
32KiB. Redirects are rejected, TLS verification is enabled, transport retries and
environment-derived proxies are disabled. Explicit custom transports must honor
cancellation and maintain security properties.

## Data sent

Detection receives a generated request ID, adapter mode, normalized route, method,
client IP, timestamp, header names, User-Agent, Accept-Language and Accept-Encoding.
Those three header values are untrusted metadata. Prompts, bodies, model outputs,
authorization/cookie values and trusted local-rule context are not serialized.
Reports contain decision/check metadata and handler outcomes, without IPs or header
values. Do not put sensitive identifiers in rule IDs, reason codes or route templates.

## Development

```sh
python -m pip install -e '.[dev]'
python -m unittest discover -s tests -v
python -m build
```

Tests use deterministic service/model fixtures. They establish integration behavior,
not detection effectiveness, customer savings, or production capacity.
