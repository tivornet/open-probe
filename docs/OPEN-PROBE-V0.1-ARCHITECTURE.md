# Open Probe V0.1 Architecture

Status: architecture gate  
Platform: macOS Apple Silicon first  
Authority: the controlling documents in `../../docs/`

## Product scope

Open Probe measures local AI network paths transparently and reproducibly. It produces normalized local evidence; it does not score networks, rank paths, change routes, operate a proxy, repair connectivity, or run continuously.

```text
Probe Core
  → Check Registry
  → Protocol Measurements
  → Provider Adapters
  → Normalized Evidence
  → Local Report
  → Deterministic Redaction
  → Explicit JSON Export
```

Every layer has one responsibility:

- **Probe Core:** lifecycle, deadlines, cancellation, clock, run identity, concurrency limits.
- **Check Registry:** versioned declarations and dependency graph; no execution code.
- **Protocol Measurements:** reusable DNS, TCP, TLS, HTTPS, WebSocket, address-family, interface, route, egress, and ASN capabilities.
- **Provider Adapters:** declare what to measure, why it matters, and how generic outcomes map to bounded provider-path interpretations.
- **Normalized Evidence:** immutable observations with provenance, timing, limitations, and typed errors.
- **Local Report:** human summary and full machine result derived from the same evidence.
- **Redaction:** deterministic transformation and policy validation.
- **Export:** explicit user action; writes only a redacted, schema-valid artifact.

## Repository and package architecture

The target repository layout is designed as a portable core with one macOS adapter. Directories marked `future` are not V0.1 implementation authorization.

```text
probe/
├── README.md
├── LICENSE                         # decision gate
├── SECURITY.md                     # implementation slice
├── CONTRIBUTING.md                 # implementation slice
├── docs/
├── schemas/
├── registry/
├── crates/                         # proposed Rust workspace; decision pending
│   ├── probe-contracts/             # schema types and validation
│   ├── probe-core/                  # orchestration only
│   ├── probe-measurements/          # protocol capabilities
│   ├── probe-provider-adapters/     # declarative compositions
│   ├── probe-redaction/             # deterministic export policy
│   ├── probe-platform-macos/        # read-only interface/route implementation
│   └── tivor-probe-cli/             # command surface
├── fixtures/
├── tests/
│   ├── contract/
│   ├── redaction/
│   ├── integration/
│   └── adversarial/
└── packaging/                       # future signed release work
```

Rust is the recommended implementation language because a single auditable binary, strict types, memory safety, and future portability fit the product. This is a recommendation, not authorization to scaffold code in this gate.

## Measurement execution model

1. Load embedded signed/reviewed registry versions.
2. Validate registry and provider adapter contracts before network access.
3. Build a deterministic check plan from user-selected providers/capabilities.
4. Show preflight: checks, destinations by purpose, permissions, time budget, and local-output behavior.
5. Execute bounded independent checks; one failure never aborts unrelated checks.
6. Normalize raw results without provider-specific transport code.
7. Render a local summary and keep the complete private result local.
8. On explicit export, redact, validate, scan for forbidden material, then atomically write.
9. If any export safety check fails, write nothing and return `export.redaction_failed`.

## Determinism and reproducibility

- Registry, check, adapter, schema, tool, redaction-policy, and platform-adapter versions are recorded.
- A check has explicit inputs, deadline, retry policy, address-family policy, and normalization version.
- Wall-clock timestamps describe execution; monotonic durations measure timing.
- Concurrency may change timing but not result semantics or output ordering.
- JSON uses stable key/array ordering where defined and RFC 3339 UTC timestamps.
- Dynamic values such as IPs are observations, not implicit health conclusions.

## Provider boundary

A provider adapter may:

- reference generic measurement definitions;
- supply reviewed endpoint references and protocol options;
- explain purpose and user impact;
- define bounded interpretation rules for reachability, challenge, incomplete evidence, and limitations.

It may not implement DNS/TCP/TLS/HTTPS/WebSocket clients, read credentials, access cookies, mutate routes, infer provider-wide outages from one local failure, or contain reliability scoring/ranking.

## Separation from other Tivor layers

- Free Web can explain or consume explicitly exported redacted artifacts later.
- Open Probe contains open measurements, schemas, and redaction.
- Intelligence Backend scoring, history, correlations, and ranking are absent.
- Pro monitoring, routing, repair, guard, and portal automation are absent.
- Private products and machine-specific runtimes are not dependencies.
