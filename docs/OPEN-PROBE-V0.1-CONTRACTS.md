# Open Probe V0.1 Contracts

## Measurement registry

The registry is data, not executable code. Each entry has:

- stable `measurement_id` and semantic `version`;
- one generic `capability`;
- declared inputs and sensitivity classification;
- timeout, retry, and address-family policy;
- expected evidence fields;
- required permission capabilities;
- failure isolation policy;
- endpoint reference, when network access is required;
- explicit limitations.

V0.1 capabilities are `dns.resolve`, `tcp.connect`, `tls.handshake`, `https.request`, `websocket.handshake`, `ip_family.observe`, `interface.snapshot`, `route.lookup`, `egress.observe`, `asn.lookup`, and `provider.path`.

`provider.path` is a composition result. It cannot perform network I/O itself.

Registry changes are reviewed like code. An unknown capability, duplicate ID/version, unresolved endpoint reference, unsafe method, unbounded timeout, or undeclared permission makes the registry invalid before execution.

## Probe result schema

The authoritative machine contract is `../schemas/probe-result.v0.1.schema.json` with schema ID `https://schemas.tivor.net/open-probe/probe-result/v0.1`.

Top-level sections:

- `schema_version`, `tool`, `run`, and `environment`;
- `registry_versions` for reproducibility;
- `checks` containing normalized evidence and typed errors;
- `provider_paths` containing bounded adapter interpretations;
- `limitations` and `permissions`;
- `redaction` describing private/local state or an exported artifact.

The private local result may contain sensitive observations permitted by the local schema profile. Export uses the same semantic schema with the `redaction.profile = public_export_v0.1` invariant and no forbidden fields.

Schema evolution:

- additive optional fields: minor version;
- interpretation change: check/adapter version bump;
- removed/renamed fields or semantic break: major version plus migration notes;
- readers reject unsupported major versions and preserve unknown minor fields without interpreting them.

## Evidence and provenance

Every check result contains zero or more evidence records. An evidence record includes:

- stable evidence ID scoped to the run;
- check ID/version and timestamp;
- `provenance`: `observed`, `inferred`, `provider_reported`, or `unknown`;
- `state`: `healthy`, `degraded`, `unstable`, `unavailable`, `challenge`, or `incomplete`;
- confidence: `high`, `medium`, `low`, or `unknown`;
- structured value with a declared value type;
- source capability and address family where applicable;
- limitations and supporting evidence references.

Rules:

- raw protocol facts are `observed`;
- an adapter conclusion is `inferred` and cites observed evidence IDs;
- provider status data is `provider_reported` and never substitutes for the local path;
- missing, unsupported, canceled, or unsafe-to-observe facts are `unknown`/`incomplete`;
- timeout or null alone does not become `unavailable`;
- HTTP authentication or anti-bot challenge can prove path response and maps to `challenge`, not automatic failure;
- provider and local-path states remain separate.

## Error taxonomy

Errors are machine codes with a phase, retryability, safe summary, and optional causal chain. Raw system messages remain local-only and are redacted on export.

| Namespace | Examples | Meaning |
|---|---|---|
| `input.*` | `invalid_registry`, `unsupported_schema` | Contract or invocation rejected before probing |
| `permission.*` | `interface_denied`, `route_unavailable` | Read capability unavailable; no escalation implied |
| `dns.*` | `timeout`, `nxdomain`, `servfail`, `malformed_answer` | Resolver outcome |
| `tcp.*` | `timeout`, `refused`, `network_unreachable`, `reset` | TCP establishment outcome |
| `tls.*` | `timeout`, `certificate`, `protocol`, `handshake` | TLS outcome |
| `http.*` | `timeout`, `transport`, `unexpected_response`, `challenge` | HTTPS outcome |
| `websocket.*` | `timeout`, `upgrade_rejected`, `protocol` | WebSocket handshake outcome |
| `route.*` | `not_found`, `unsupported`, `ambiguous` | Local attribution outcome |
| `egress.*` | `unavailable`, `family_mismatch`, `inconsistent` | Egress observation outcome |
| `asn.*` | `unavailable`, `unknown_prefix`, `source_error` | ASN context outcome |
| `provider.*` | `partial`, `challenge`, `insufficient_evidence` | Adapter interpretation outcome |
| `run.*` | `canceled`, `deadline`, `internal` | Probe lifecycle outcome |
| `export.*` | `redaction_failed`, `forbidden_data`, `schema_invalid`, `write_failed` | Fail-closed export outcome |

An internal error cannot silently become a network failure. Each check records `complete`, `partial`, `failed`, `canceled`, or `unsupported` independently.

## Provider-path abstraction

Provider adapters conform to a versioned declaration:

```text
provider_id + adapter_version
  purpose statements
  product labels
  endpoint references
  ordered generic measurement references
  interpretation rules
  limitations
```

The initial registry has OpenAI/ChatGPT/Codex, Claude/Claude Code, Gemini, GitHub Copilot, and Cursor. Adapter declarations intentionally contain no credentials and no authenticated operations. Endpoint values remain a separate reviewed registry so they can be replaced without forking protocol logic.

## CLI contract

Proposed V0.1 surface:

```text
tivor-probe version
tivor-probe doctor
tivor-probe registry list [--provider <id>]
tivor-probe plan [--provider <id>...] [--format text|json]
tivor-probe run [--provider <id>...] [--output <private-path>]
tivor-probe report <private-result> [--format text|json]
tivor-probe redact <private-result> --output <export-path>
tivor-probe validate <result-or-export>
tivor-probe permissions
```

Contract rules:

- `run` performs measurements and writes only when `--output` is explicitly provided; otherwise it prints the human summary and retains no report file.
- `redact` is the only V0.1 path to a shareable artifact.
- no `upload`, `pair`, `watch`, `daemon`, `repair`, `route`, or proxy mutation command exists in V0.1.
- JSON stdout contains data only; diagnostics go to stderr without secrets.
- `--verbose` still applies secret-safe logging and never reveals forbidden fields.
- output files use owner-only permissions and atomic creation; existing files are not overwritten without explicit `--force`.
- exit codes distinguish success, partial evidence, invalid invocation, permission limitation, unsafe export, and internal failure.

Suggested exit codes: `0` complete, `2` valid partial/incomplete result, `10` invalid input, `11` permission limitation, `12` unsafe export blocked, `20` internal failure. Network check failures remain evidence and do not necessarily make the process fail.
