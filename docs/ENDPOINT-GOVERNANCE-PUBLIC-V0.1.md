# Endpoint Governance — Public V0.1

Provider URLs are never added ad hoc. Each endpoint entry is versioned and must pass safety, anonymous-measurement, rate/abuse, interpretation, and versioning review. The registry defines protocol, bounded purpose, expected semantics, limitations, and whether execution is enabled.

Reviews must reject endpoints that require credentials, produce side effects, expose user data, encourage scraping, or cannot support a defensible interpretation. A registry entry may be disabled without changing generic protocol code. Unsupported providers remain visible as unsupported rather than silently falling back to arbitrary URLs.
