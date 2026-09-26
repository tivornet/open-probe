# Open Probe V0.1 Security, Permissions, and Redaction

## Permission model

V0.1 requests no administrator access and installs no privileged helper.

| Capability | Mode | Default |
|---|---|---|
| Outbound DNS and network requests | disclosed, destination-bound | required for selected network checks |
| Read interface addresses/state | read-only public OS interfaces | on |
| Read route selection/table | read-only, least detail needed | on |
| Observe TUN presence | read-only and best effort | optional; unsupported is valid |
| Read system proxy summary | out of V0.1 unless separately approved | off |
| Write local result | explicit user-selected path | off until requested |
| Export redacted JSON | explicit command and output path | off until requested |
| Upload/pair | not implemented | off |
| Background execution | not implemented | off |

Permission denial produces incomplete evidence and a least-privilege explanation. It never triggers automatic elevation, route changes, DNS changes, proxy changes, or retries through another path.

## Data classes

- **Forbidden everywhere:** passwords, tokens, cookies, subscription URLs, proxy credentials, authentication headers, client secrets, private keys.
- **Private-local only:** exact IP/MAC/interface identifiers, full routes, resolver addresses, raw error strings, full endpoint URLs, local paths, hostnames not defined by the reviewed registry.
- **Export-transform:** IP addresses, interface names, resolver/route identifiers, timestamps, run IDs.
- **Export-allowed:** tool/schema/check versions, provider ID, protocol outcome class, duration buckets, IP family, country/ASN only when policy permits and source is declared, limitations, provenance, redaction metadata.

## Deterministic redaction contract

Redaction policy ID: `public_export_v0.1`.

1. Parse and validate the private result against its supported schema.
2. Traverse by schema field identity, never by UI label or provider keyword.
3. Drop all fields classified forbidden or private-only.
4. Transform approved quasi-identifiers using policy-defined operations.
5. Canonicalize ordering and timestamps according to policy.
6. Run exact-key, structured-value, URL/query, header, entropy, and secret-pattern detectors.
7. Validate the redacted artifact against the public-export invariants.
8. Generate a manifest of policy version, removed field paths, transformed field paths, and validation status without removed values.
9. Atomically write only after every check passes.

The same input plus policy version produces the same export, except explicitly documented nondeterministic metadata must be omitted. Redaction never expands an allowlist from observed data.

If parsing, traversal, transformation, secret scanning, or schema validation fails, export fails closed and no partial output remains.

## Initial export transformations

- exact IP: removed by default; optional prefix preservation is not approved in V0.1;
- MAC address: removed;
- interface name: stable category (`wifi`, `ethernet`, `tunnel`, `loopback`, `other`) rather than raw name;
- local file path: removed;
- URL: replace with reviewed endpoint reference and strip query/fragment/userinfo;
- timestamp: retain RFC 3339 UTC for evidence chronology;
- run/evidence identifiers: regenerate deterministic export-scoped IDs;
- raw error: map to taxonomy code and safe static summary;
- DNS answers and route gateways: remove exact address, retain family/count/outcome where approved.

## Threat model

### Assets

- local network topology and identifiers;
- user privacy and credentials in process environment/configuration;
- integrity of measurements, registries, schemas, and exports;
- trust in release artifacts and update instructions;
- provider endpoints protected from abusive scanning.

### Adversaries and failures

- malicious/captive DNS or HTTP response;
- hostile TLS/WebSocket endpoint payload;
- compromised or poisoned registry entry;
- symlink/path traversal or overwrite on local export;
- secret leakage through URLs, errors, environment variables, crash dumps, logs, or exports;
- command injection through endpoint or adapter data;
- resource exhaustion via oversized responses, slow connections, DNS fan-out, or retry storms;
- false claims caused by partial evidence, challenges, dual-stack divergence, clock changes, or backend outage;
- supply-chain compromise of dependencies, binary, package, or update channel;
- future pairing/upload accidentally bypassing redaction.

### Controls

- embedded/reviewed registries; no arbitrary user URL in provider checks;
- HTTPS/WSS only for provider network checks unless a separately reviewed diagnostic explicitly requires otherwise;
- response size/time/concurrency/retry bounds;
- no shell interpolation and no dynamic code loading;
- certificate validation on by default with no insecure bypass flag in V0.1;
- owner-only atomic file creation, symlink refusal, and explicit overwrite;
- structured secret-safe logging;
- independent evidence and typed limitations;
- schema validation before and after redaction;
- dependency lock, audit, SBOM, checksum, signing, and reproducible-build gates before release;
- fuzzing for parsers/redaction and adversarial fixtures for untrusted responses.

## Explicit non-goals

V0.1 does not defend a device already fully compromised, prove the physical network path, detect every VPN/proxy, determine account eligibility, establish a provider-wide incident, or provide anonymity. It does not mutate the system to remediate an observation.
