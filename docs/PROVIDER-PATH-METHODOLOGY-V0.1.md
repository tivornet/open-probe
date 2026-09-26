# Provider Path Methodology V0.1

The core implements reusable DNS, TCP, TLS, HTTPS, WebSocket, interface, route, egress, and ASN measurements. Provider adapters only select governed checks and explain their diagnostic meaning. They do not duplicate protocol logic.

Execution is bounded, anonymous, rate-limited by the CLI plan, and disabled unless the user passes `--provider-path`. Each observation records provenance, timing, limitation, and endpoint-registry version. Authentication challenges, partial evidence, and unsupported checks are not provider outages. The output is path evidence, not a health verdict, score, ranking, or root-cause claim.
