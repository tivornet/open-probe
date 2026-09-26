# Endpoint Governance V0.1

Every executable endpoint is a versioned security and interpretation decision, not a URL list.

An endpoint is executable only when `SAFETY_REVIEW`, `ANONYMOUS_MEASUREMENT_REVIEW`, `RATE_ABUSE_REVIEW`, `INTERPRETATION_REVIEW`, and `VERSIONING_REVIEW` are all `pass`, its status is `approved_canary`, and its budget is bounded.

The default is disabled. `tivor doctor --local` never selects a live endpoint. A human must explicitly add `--live-canary`.

## Approved in review 1.0.0

- `openai.primary_https`: official documented `GET /v1/models`, without an Authorization header. A 401/403 means only that an HTTP responder and authorization/challenge path were observed.

## Unsupported

Anthropic, Gemini, GitHub Copilot, and Cursor remain `UNSUPPORTED_LIVE_CANARY`. Authenticated APIs, wildcard allowlists, status pages, and browser application pages do not by themselves provide a defensible anonymous product-path measurement contract.

## Privacy and budgets

No Authorization, Cookie, Set-Cookie, request body, response body retention, account identifier, key, token, or credential is allowed. One provider failure is isolated from all others. The first approved endpoint permits one request, no retries, no redirects, one per-host concurrent request, five seconds, and 16 KiB.
