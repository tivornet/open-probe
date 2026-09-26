# Redaction Specification V0.1

The public-export transformation is deterministic and fail closed.

Removed classes include exact public/private/local IPs, MAC addresses, hostname and user identity, credentials, tokens, cookies, authorization material, proxy credentials, subscription URLs, arbitrary configuration, response bodies, and secret-like values. Allowed classes include IP family, justified ASN/network organization, normalized check outcome, provenance, bounded timings, limitations, and contract-defined timestamps.

Pipeline: private result → deterministic transform → forbidden-key scan → secret-pattern scan → public schema validation → atomic rename. Any failure removes the temporary output and returns an error. Negative fixtures intentionally contain synthetic forbidden keys, documentation IPs, and fake tokens; they are test data, not operational secrets.
