# Zero-Liability: Provisioning KMS Keys

## Enterprise Configuration UI

Cicada specifically targets the reduction of legal liability by ensuring your Master AI Keys never touch plain-text database logic.

To configure a new agent or add Anthropic/OpenAI Swarm capability, an Administrator must generate a `CiphertextBlob`.

### The Provisioning Flow
1. Navigate to the **Vault & Keys** module on the Cicada Dashboard.
2. In the "Client KMS & Routing" section, paste your literal API key into the target `<SecureInput>` field.
3. Upon clicking Bind, Cicada will initiate a strict HTTPS POST trace. The browser physically drops the text input via DOM overriding directly post-send to ensure no browser history stores the private keys.
4. The Go Sentry Gateway mathematically seals the string mapped uniquely to your `TenantID`, saving exclusively the unreadable Cipher configuration.
