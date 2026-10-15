# Cicada MCP & SDK Sidecar Adapter

The **Cicada SDK Sidecar** is a compiled local runtime proxy designed for Zero-Trust enterprise API verification. It enables developers building Python, Node, Go, or LangGraph intelligence agents to authenticate using their `CICADA_EVAR` natively, while shielding their application payloads from the heavy cryptographic lifting.

By employing the "Base URL Override / Reverse Proxy" architecture instead of invasive SSL `CONNECT` MITM certificates, installation requires zero host-machine configuration, avoiding frustrating firewall debug sessions natively.

## How it works

1. Place the compiled `cicada-sidecar` binary in your local agent repository.
2. Provide your single permanent token in the environment (`CICADA_EVAR=your_token_here`).
3. Point your LLM or framework's API Target to the local sidecar (`http://localhost:7777`).
4. Append the true desired destination in the HTTP Request Headers:
   `X-Cicada-Target-URL: https://api.stripe.com/v1/charges`

The Sidecar performs all token exchanges, session rotations (15m limits), and encrypted TLS handshakes with the Central Sentry Gateway natively.

---

## Integrations

### Python (Requests / Base)

```python
import os
import requests

# 1. Boot the Cicada Sidecar manually (or wrap inside your bash startup)
# $ export CICADA_EVAR=xxxx && ./cicada-sidecar

# 2. Configure HTTP calls
url = "http://localhost:7777/v1/charges"
payload = {"amount": 5000, "currency": "usd"}
headers = {
    "X-Cicada-Target-URL": "https://api.stripe.com/v1/charges",
    "Content-Type": "application/x-www-form-urlencoded"
}

# 3. Proceed as normal - zero SSL certificate errors due to Proxy override.
response = requests.post(url, data=payload, headers=headers)
print(response.json())
```

### LangGraph / LangChain

Override standard HTTP configurations inside the API wrappers:

```python
from langchain_community.utilities import RequestsWrapper

# Let the wrapper talk to the local sidecar natively
wrapper = RequestsWrapper(headers={"X-Cicada-Target-URL": "https://api.exa.ai/search"})

# Point your API target at the Proxy
result = wrapper.get("http://localhost:7777/search?q=enterprise+AI+policies")
```

### Claude / Cursor (MCP JSON-RPC Tethers)

If utilizing the `POST /v1/mcp` capability out of the box in your IDE:

```json
{
  "mcpServers": {
    "cicada-sentry": {
      "command": "/path/to/cicada-sidecar",
      "args": [],
      "env": {
        "CICADA_EVAR": "your-evar-identity-key-here",
        "CICADA_GATEWAY_URL": "https://core-gateway.yourcompany.internal"
      }
    }
  }
}
```

The sidecar transparently manages the session state, so your IDEs never leak identity secrets into the console logs.
