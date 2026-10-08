# Changelog

## 0.1.0b1

First beta of the Python AI Protection SDK. The `webdecoy_ai_protection` package
API is unchanged from `0.1.0a1`; this release moves the package from alpha to beta.

- Add a runnable Ollama example (`examples/ollama_budget.py`) that wraps one
  non-streaming `ollama.AsyncClient.generate` call in a per-attempt model budget,
  with pinned example requirements (`examples/requirements-ollama.txt`).
- Add tests for the Ollama example against the pinned `ollama==0.6.3` Python SDK
  with an in-memory HTTP transport: serialization, usage normalization, denial
  before the provider, privacy, cancellation and accounting failures. `ollama` is
  added to the `dev` extra only; it is not a runtime dependency.
- Document the Ollama example in the README.
- The publish workflow now accepts beta (`bN`) as well as alpha (`aN`)
  pre-release versions.
- Update maturity labels and install instructions to `0.1.0b1`.

```sh
python -m pip install 'webdecoy-ai-protection[fastapi]==0.1.0b1'
```

Earlier releases are described in the
[GitHub releases](https://github.com/WebDecoy/ai-protection-python/releases).
