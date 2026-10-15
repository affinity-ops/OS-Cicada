# Cicada Licensing Authority

The **Licensing Authority** is a standalone, isolated, highly-secure Go service responsible for generating, revoking, and validating cryptographic license keys (`.lic` files) for Enterprise Self-Hosted Sentry Gateways.

## Architectural Posture
This service is intentionally decoupled from the public-facing `Core_API` and `Developer_Portal`. It holds the Cicada Master Private Key. It is designed to be run in an air-gapped or heavily restricted internal network segment accessible only by Cicada operators. 

By isolating this service, a breach of the public web infrastructure does not grant attackers the ability to mint valid enterprise Gateway licenses.

## Documentation
- [Roadmap & Verification Ledger](docs/ROADMAP.md) - Tracks the build state of the Licensing Authority.
