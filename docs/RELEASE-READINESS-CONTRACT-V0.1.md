# Release Readiness Contract V0.1

The result contract computes `release_readiness` from actual normalized evidence.

- Required: `openai`, `anthropic`.
- Optional in V0.1: `google_gemini`, `github_copilot`, `cursor`.
- Required coverage passes only when governed evidence exists with state `observed` or `challenge`.
- Coverage pass never means provider health.
- Optional providers without governed live evidence are `unsupported`, not unavailable.

The gate is `ready` only when both required providers pass. Recorded deterministic fixtures test positive and negative behavior; CI never depends on a real provider.

