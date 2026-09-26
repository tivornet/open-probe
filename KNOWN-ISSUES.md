# Known Issues — V0.1 Public Beta

- Only macOS 13+ Apple Silicon is supported.
- Provider path evidence is not a provider-health verdict.
- OpenAI coverage is bounded to governed anonymous path evidence.
- Anthropic coverage is DNS/TCP/TLS path evidence; application or account availability is not tested.
- Gemini, GitHub Copilot, and Cursor are unsupported and remain unexecuted.
- Captive portals, enterprise interception, and local filtering can make evidence incomplete.
- Network identity can change between measurements; a single observation is not historical intelligence.
- Long-connection evidence is unavailable because no safe anonymous persistence endpoint is approved.
- On macOS 26.6.2, a direct `codesign -R=notarized --check-notarization` diagnostic may disagree with Gatekeeper even when the quarantined CLI is accepted as Notarized Developer ID; tracked post-Beta.
