# Privacy and Data Behavior

Open Probe runs locally. It has no account, analytics, background telemetry, upload endpoint, or silent sharing path.

`tivor doctor` observes bounded local interface and route facts and makes no provider request. `tivor doctor --provider-path` is an explicit opt-in to the versioned, governed anonymous endpoints in the repository. It does not use credentials.

Private local results may contain exact observed public IPs, local interface evidence, timestamps, and route facts when diagnostically necessary. They remain on the device unless the user explicitly moves them. Public export removes exact public and private IPs, MAC addresses, hostnames, credentials, tokens, cookies, proxy credentials, subscription URLs, arbitrary configuration, and secret-like values. ASN/network organization, IP family, normalized evidence, provenance, limitations, and contract-defined timestamps may remain. Any redaction, secret scan, or schema failure prevents export.

The tool never collects passwords, authentication tokens, browser cookies, subscription URLs, or proxy credentials.
