# WebDecoy AI Protection for Python

Async request admission for Python AI endpoints. Local application rules run in
your process; bot detection runs in WebDecoy. Apache-2.0 licensed.

**Development preview, not published to PyPI.** This first implementation covers
admission, shared account/session quotas, reporting and an explicit FastAPI/Starlette
route wrapper, including optional concurrency leases across streamed responses.
Model-budget accounting, browser evidence and MCP adapters are not yet
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

## Shared account quotas

```python
from webdecoy_ai_protection import AccountQuota, QuotaSubject

quota = AccountQuota(
    rule_id="chat_v1",
    subject_secret=server_subject_secret,  # At least 32 UTF-8 bytes; use a random secret.
    subject=lambda ctx: QuotaSubject(ctx["account_id"], ctx["session_id"]),
    limit=100,
    session_limit=20,  # Optional; supplements the account limit.
    window_seconds=3600,
    mode="observe",
    failure_mode="open",
    idempotency=True,
)
# Pass account_quota=quota when creating Client. Pass authenticated, authorized
# server state as context to check() or protect(); never use browser identity claims.
```

All replicas (including Node/Go) must use the same property, rule ID, secret and
policy. The SDK sends length-framed HMAC-SHA256 pseudonyms, never raw account or
session IDs. Changing the secret creates different buckets; keep it stable and
private. The backend fixes the policy for each rule ID; changed limits/window
produce a policy conflict rather than resetting the quota.

The order is **local rules → shared quota → detector → your handler**. Enforced
local denials consume no quota; a later detector denial or model failure does not
refund consumed admission. Observe mode also consumes the shared quota but allows
requests that exceed it. Quota enforcement is independent of detector/dashboard
mode. Use `mode="enforce"` to return 429 with `Retry-After` when exhausted, and
`failure_mode="closed"` to return 503 when shared state is unavailable. Defaults
are observe/open; fail-open cannot guarantee a hard request limit.

`decision.quota` exposes the check, remaining/reset values when confirmed, and an
optional recovery operation ID. `decision.retry_after_seconds` is set on enforced
quota denials; the FastAPI wrapper sets the HTTP header automatically.

With `idempotency=True`, schema 2 retries an uncertain quota RPC at most once,
using exactly the same payload and operation ID. Each attempt has its own `timeout`
(default 1 second, maximum 10). Without this option, schema 1 makes one attempt.
Terminal responses below HTTP 500 are not retried. An ambiguous response becomes
`account_quota_outcome_unknown`; a later expiration error does not erase that
uncertainty. Cancellation propagates without retrying or admitting the request.

For recovery across request/process loss, generate `new_quota_operation_id()` and
persist it in trusted server state **before** admission; return it from the quota's
optional `operation_id(context)` callback. The backend recovery window is ten
minutes. Do not replace an uncertain operation with a new ID. Generated receipts
are available on `decision.quota.operation_id` when a decision returns; a cancelled
call may produce no decision. Recovery receipts are not sent in central reports.
**An admission receipt does not deduplicate model execution.** The application
must separately ensure a replay cannot run a model/tool side effect twice.

## Shared concurrency leases

```python
from webdecoy_ai_protection import Concurrency, QuotaSubject

concurrency = Concurrency(
    rule_id="chat_concurrency_v1",
    subject_secret=server_subject_secret,
    subject=lambda ctx: QuotaSubject(ctx["account_id"]),
    account_limit=2,
    feature_limit=20,
    ttl_seconds=30,
    max_seconds=300,
    mode="observe",
    failure_mode="open",
)
# Pass concurrency=concurrency to Client.
```

With FastAPI `protect()`, configuring concurrency automatically acquires a lease
**after ordinary admission and before calling your handler**, then renews it until
the original response stream and background tasks finish. The wrapper includes the
concurrency check in the single central outcome report. Exhausted enforced capacity
returns 429 with `Retry-After`; closed acquisition failures return 503.

For core-client integrations, call `check()` first and enforce that decision, then
use `await client.run_concurrent(context, deferred_async_work)`. The result exposes
`allowed`, `status`, `retry_after_seconds`, `check`, `leased`, `released`, and the
work's return `value`. This helper does not run ordinary admission or emit a separate
central report. Core callers own their normal decision/outcome reporting.

**The work callback must consume and await all provider work before returning.**
Returning an async iterator, `StreamingResponse`, or detached task is not completion;
consume the stream inside the callback. The FastAPI wrapper handles the ASGI response
lifetime for you. All work must cooperate with asyncio cancellation.

- Account and feature capacity is shared across replicas using the same property,
  rule ID, secret and immutable backend policy. Raw account IDs stay in-process.
- Observe mode can grant a lease while recording that capacity was exceeded. A
  replayed acquisition never authorizes another execution, even in observe mode.
- Acquisition makes one bounded RPC and never retries. Its failure policy is
  independent of quota and detector policies. Fail-open work has no confirmed lease
  and cannot promise a hard concurrency cap.
- Once acquired, failed/invalid renewal cancels work regardless of observe/enforce
  or acquisition failure policy. `ConcurrencyLeaseLost` propagates; if a stream
  already started, its HTTP status cannot be replaced with a new denial response.
- Work also has a `max_seconds` deadline (including acquisition time), even when
  acquisition failed open. The SDK uses monotonic time and charges network time
  against the lease lifetime.
- Only confirmed normal completion releases capacity. Errors, cancellation and
  uncertain acquisition retain any server reservation until its maximum deadline.
  Stopping renewal or hitting the shorter TTL does **not** free that reservation.
  Cancellation does not prove an upstream provider stopped.
- Release makes one bounded RPC. Failure returns the completed work's value with
  `released=False`; it never raises an accounting error that invites a model retry.
  FastAPI preserves the response and logs a content-free warning. No provider work
  is automatically retried.

Timeout defaults to one second, maximum `min(10, ttl_seconds / 6)`; TTL range is
6–120 seconds, maximum runtime range is TTL–900 seconds. Drain active requests
before closing the client. Account limits are 1–1,000 and feature limits are at
least the account limit, up to 10,000. This is cooperative admission control, not
proof of provider completion or a spending guarantee.

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
environment-derived proxies are disabled. Optional schema-2 quota recovery has
its own bounded retry described above. Explicit custom transports must honor
cancellation and maintain security properties.

## Data sent

Detection receives a generated request ID, adapter mode, normalized route, method,
client IP, timestamp, header names, User-Agent, Accept-Language and Accept-Encoding.
Those three header values are untrusted metadata. Prompts, bodies, model outputs,
authorization/cookie values and trusted local-rule context are not serialized.
When quotas are enabled, quota RPCs also send the rule ID, policy values, hashed
account/session identifiers and (for schema 2) a recovery operation ID.
Concurrency RPCs send policy values, the hashed account identifier and an acquisition
nonce or lease ID; lease identifiers are not included in central reports.
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
