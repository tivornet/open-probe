# AI Network Measurement Matrix V0.1

Slice 10 adds provider-neutral short-window measurement and deterministic analysis. The chain remains: protocol measurement → normalized evidence → repeated sampling → ReliabilitySnapshot → reliability analysis → failure localization → human explanation.

The governed default window is 25 seconds, interval 5 seconds, concurrency 1, and retry budget 0. Each attempt is evidence; a failed attempt is not silently retried. `adjacent-mad-v0.1` jitter is the arithmetic mean of absolute differences between consecutive successful latency samples.

Reliability thresholds are conservative and local to the window: fewer than three samples is `INSUFFICIENT_DATA`; a worst-stage success rate below 80% or failure burst of two is `UNSTABLE`; any lesser failure or p95 above four times p50 and above 500 ms is `DEGRADED`; otherwise it is `STABLE`. These states are not a commercial score or globally calibrated quality claim.

Failure localization reports only DNS, TCP, TLS, HTTPS, LONG_CONNECTION, MULTI_STAGE, NONE_OBSERVED, or UNKNOWN. It never attributes blame. Long-connection evidence is `NOT_AVAILABLE` because no safe anonymous persistence endpoint is approved.

Anthropic V0.1 remains DNS/TCP/certificate-validated TLS only. Its authenticated API is not a safe anonymous HTTPS measurement contract, so application-layer evidence is unavailable and confidence is limited. OpenAI retains its approved anonymous HTTPS responder path. No response body is retained.
