# Understanding Ghost Mode & Threat Intercepts

## The Shadow AI Discovery Module

**Shadow AI** occurs when unauthorized, un-credentialed agents begin operating inside your network boundary. Cicada handles these natively to gather adversarial Threat Intelligence without alerting the intrusive bot.

### How Ghost Mode Works
When Cicada identifies a missing or mathematically revoked EVAR Token, it strips the agent of actual DB access but returns a simulated `200 OK`. 
- For a `POST` or `DELETE`, Cicada generates a mock ID, saving the action payload strictly in the temporary `GhostLedger`.
- For subsequent `GET` requests, the Sentry node references the fake ID, returning generated data to preserve the illusion.
- The C-Suite Operator can trace and track the breach vector silently from the Cicada Dashboard before initiating a hard cut-off.
