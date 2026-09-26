# Probe Result Schema V0.2

`schemas/probe-result.v0.2.schema.json` is the normative machine contract. A result records the schema version, run identity and time, execution mode, platform, checks, normalized evidence, provenance, errors, limitations, and export state.

Evidence is typed rather than free-form. Provenance distinguishes observed facts from inferred or unavailable facts. Missing evidence stays missing; it is never converted into provider unavailability. Private-local results may contain fields classified as sensitive. Public exports must use the public profile, deterministic redaction, secret scan, schema validation, and atomic write. A failed stage produces no export.

Consumers must reject unknown major schema versions and preserve unknown compatible fields only when the schema permits them.
