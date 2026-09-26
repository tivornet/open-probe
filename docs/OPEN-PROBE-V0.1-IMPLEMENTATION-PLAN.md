# Open Probe V0.1 Implementation Plan

This plan does not authorize implementation beyond the architecture gate.

## Test strategy

### Contract tests

- JSON Schema accepts canonical complete and partial fixtures.
- Unsupported major schema and registry versions fail safely.
- Every registry ID/version is unique and every provider reference resolves.
- Provider adapters cannot declare undeclared permissions or executable logic.
- Stable serialization ordering and schema-version migration fixtures.

### Measurement unit tests

- success, timeout, refusal, reset, malformed response, cancellation, and deadline for each protocol capability;
- DNS NXDOMAIN/SERVFAIL/multiple answers and IPv4/IPv6 separation;
- TLS certificate/protocol/handshake classification without disabling validation;
- HTTPS 2xx/3xx/4xx/5xx/challenge, bounded body, and redirect policy;
- WebSocket upgrade success/rejection/timeout;
- route/interface unsupported and permission-denied outcomes;
- address-family and provider-path partial evidence.

### Redaction and adversarial tests

- golden deterministic exports;
- forbidden key/value corpus for credentials, cookies, URLs, headers, portal queries, and high-entropy tokens;
- nested/unknown fields, malformed JSON, Unicode confusables, encoded URLs, IPv4/IPv6, MACs, and local paths;
- redaction failure leaves no output;
- symlink, overwrite, traversal, and interrupted atomic write;
- fuzz structured parsers and redaction traversal.

### Integration tests

- local deterministic DNS/TCP/TLS/HTTPS/WebSocket fixture servers;
- no public provider dependency in default CI;
- opt-in live canary suite with strict rate limits and no release gating on provider availability;
- macOS Apple Silicon route/interface snapshots using recorded sanitized fixtures;
- offline execution still renders an incomplete local result;
- one check failure preserves all unrelated results.

### Acceptance fixtures

At minimum: healthy, degraded, challenge, incomplete, single-check timeout, backend/endpoint unavailable, mixed IPv4/IPv6, captive portal/interstitial, dynamic multi-egress, permission denied, canceled run, malicious response, and unsafe export.

## Implementation slices

### Slice 1 — Contracts and deterministic local skeleton

- decide license and implementation language;
- establish repository governance, security policy, contribution rules, and dependency policy;
- implement schema types/validation and registry validation;
- implement run lifecycle with injected clock/transport abstractions;
- implement local fixtures, canonical serialization, and CLI `version`, `registry list`, `plan`, and `validate`;
- no live provider endpoints yet.

Exit: contract fixtures and invalid-input tests pass on macOS Apple Silicon.

### Slice 2 — Protocol measurement core

- implement bounded DNS, TCP, TLS, HTTPS, and WebSocket measurements once;
- add IP-family observation and safe timing;
- use deterministic local fixture servers before any live endpoint;
- normalize typed evidence/errors.

Exit: protocol tests, cancellation, resource limits, and partial-result behavior pass.

### Slice 3 — macOS read-only platform adapter

- interface categories, address families, route lookup, and best-effort tunnel presence;
- no private Apple API and no administrator access;
- record unsupported/denied evidence explicitly.

Exit: read-only audit and sanitized fixture replay pass; no network/system mutation occurs.

### Slice 4 — Egress/ASN and provider adapters

- review minimal first-party or controlled diagnostic endpoints;
- implement egress and ASN observations as generic capabilities;
- populate five thin provider declarations using endpoint references;
- keep challenge and incomplete semantics distinct from unavailable.

Exit: all five providers can produce independent partial results without credentials.

### Slice 5 — Local report and fail-closed export

- synchronize human summary with machine evidence;
- implement private local result, deterministic redaction, preview, and explicit export;
- secret-pattern and adversarial gates;
- safe atomic owner-only files.

Exit: unsafe export cannot produce an artifact; offline-first run is useful.

### Slice 6 — Release engineering

- license, source/build docs, install/uninstall, data directories, changelog, known issues;
- dependency audit, SBOM, checksums, signatures, provenance, reproducible build assessment;
- security contact and responsible disclosure;
- website remains truthful until artifacts exist.

Exit: all release requirements in the Open Probe UX specification are proven.

## Open questions requiring owner decisions

1. Open-source license: Apache-2.0, MPL-2.0, or another approved license?
2. Confirm Rust workspace versus Swift-first native implementation.
3. Minimum supported macOS release and notarization/signing identity.
4. Package channel for V0.1: signed archive, Homebrew, or both.
5. Which controlled endpoints may be used for egress/ASN observations, and what retention/logging do those operators apply?
6. Which anonymous provider endpoints are stable, permitted, rate-safe, and meaningful for each adapter?
7. Should exact IP/ASN remain private-only in V0.1 export, or may explicit user-selected export include them?
8. Is TUN presence in V0.1, given it may be incomplete without elevated/private APIs, or deferred?
9. Maximum default run duration, concurrency, per-host rate, and retry budget.
10. Whether a private local result file is opt-in only or written by default to a documented app data directory.
11. Maintainer identity, security contact, repository host, and release-signing custody.
12. Whether later pairing belongs to V0.2 rather than V0.1; no upload exists in the present plan.

## Recommended next implementation slice

After the owner resolves license, language, minimum macOS, and export-IP policy, implement **Slice 1 only**: repository governance, schema/registry validators, deterministic fixtures, and a no-network CLI plan/validate skeleton. Do not begin live probing in the same slice.
