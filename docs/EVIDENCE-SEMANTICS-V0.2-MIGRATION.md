# Evidence Semantics V0.2 Migration

## Why V0.2 exists

V0.1 reused health-oriented values for observations. That allowed a parsed interface, route, or TUN-like record to appear as `healthy`, even though it proved only that a bounded observation succeeded. V0.2 removes that ambiguity.

## Canonical evidence states

- `observed`: the declared fact was directly observed.
- `available` / `unavailable`: a narrowly scoped capability was established or not established.
- `incomplete`: evidence is insufficient for the declared conclusion.
- `unsupported`: the layer is deliberately not implemented or governed.
- `challenge`: an authorization or provider challenge was observed; it is not unavailability.
- `unknown`: no defensible state is available.

Platform observations now use `observed` with `medium` confidence. Confidence refers only to the declared structural observation, never overall network or provider health. Validated, governed protocol evidence may use `high` for the exact recorded layer outcome while still withholding provider health.

## Compatibility

- V0.1 remains as a historical schema and fixture.
- New results declare `schema_version: 0.2.0`.
- V0.2 adds provider product labels and a machine-verifiable release-readiness object.
- Fixtures were copied and migrated; no V0.1 artifact is silently reinterpreted.

