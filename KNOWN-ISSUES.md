# Known Issues — V0.1 Public Beta

- Only macOS 13+ Apple Silicon is supported.
- Provider path evidence is not a provider-health verdict.
- OpenAI coverage is bounded to governed anonymous path evidence.
- Anthropic coverage is DNS/TCP/TLS path evidence; application or account availability is not tested.
- Gemini, GitHub Copilot, and Cursor are unsupported and remain unexecuted.
- Captive portals, enterprise interception, and local filtering can make evidence incomplete.
- Network identity can change between measurements; a single observation is not historical intelligence.
- Signed/notarized distribution is blocked until the Apple release gate is complete.
