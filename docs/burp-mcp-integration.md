# Burp Suite MCP Integration

The bugbug workstation integrates with Burp Suite via MCP (Model Context Protocol),
giving Claude Code direct access to Burp's proxy history, repeater, scanner, spider,
and sitemap through a loopback-only SSE connection.

## Architecture

```
┌──────────────────────┐     SSE (127.0.0.1:9876)     ┌──────────────────────┐
│   Claude Code        │ ◄──────────────────────────► │   Burp Suite         │
│   (MCP Client)       │   JSON-RPC + SSE events      │   + MCP Extension    │
│                      │                              │                      │
│   .mcp.json          │                              │   PortSwigger MCP    │
│   configures         │                              │   Extension          │
│   connection         │                              │   (BApp Store)       │
└──────────────────────┘                              └──────────────────────┘
                                                                │
                                                        ┌───────┴───────┐
                                                        │  Burp Proxy   │
                                                        │  127.0.0.1    │
                                                        │  :8080        │
                                                        └───────────────┘
```

## Prerequisites

- **Burp Suite Professional** or **Community Edition** 2024+
- **Java 17+** (OpenJDK or Oracle)
- **PortSwigger MCP Extension** installed from BApp Store

## Installation

### 1. Install Burp Suite

**Arch Linux (AUR):**
```bash
yay -S burpsuite-pro       # Professional
# or download Community from https://portswigger.net/burp/communitydownload
```

**macOS:**
```bash
brew install --cask burp-suite-professional
```

**Manual install (Linux):**
```bash
curl -o burp_installer.sh "https://portswigger-cdn.net/burp/releases/download?product=community&type=linux"
chmod +x burp_installer.sh
./burp_installer.sh -q -dir /opt/BurpSuiteCommunity
```

### 2. Install the MCP Extension

1. Open Burp Suite
2. Go to **Extensions** → **BApp Store**
3. Search for **"MCP Server"**
4. Click **Install**
5. Verify the extension is loaded in **Extensions** → **Installed**

The MCP server starts automatically on `http://127.0.0.1:9876/`.

### 3. Verify Installation

```bash
# Check MCP server is responding
curl http://127.0.0.1:9876/
# Expected: event: endpoint
#          data: ?sessionId=...

# Check Burp proxy is listening
curl -x http://127.0.0.1:8080 http://example.com/ -o /dev/null -w "%{http_code}"
# Expected: 200 (or redirect)
```

## Configuration

### Project-level `.mcp.json`

Create `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9876/"
    }
  }
}
```

The bugbug project ships with a pre-configured `.mcp.json` for Burp.

### Scope Configuration (bugbug)

The `src/hackbot/mcp/burp.py` module provides typed configuration:

```python
from hackbot.mcp.burp import BurpMCPConfig, configure_burp_mcp, burp_tool_classification

# Safe defaults (recommended)
config = BurpMCPConfig(
    base_url="http://127.0.0.1:9876",
    target_approval_enabled=True,
    config_editing_enabled=False,
    redact_sensitive_headers=True,
    exclude_cookies=True,
    exclude_bearer_tokens=True,
)

# Generate Claude Code MCP configuration
mcp_config = configure_burp_mcp(config)
# -> {"burp": {"type": "sse", "url": "http://127.0.0.1:9876/sse", ...}}

# Classify tools by risk level
classification = burp_tool_classification()
# -> {"read_only": [...], "state_changing_l1": [...], "state_changing_l2": [...]}
```

### Security Model

The bugbug Burp integration enforces strict security boundaries:

| Setting | Default | Purpose |
|---------|---------|---------|
| `base_url` | `http://127.0.0.1:9876` | **Loopback only** — never exposed on network |
| `target_approval_enabled` | `true` | Approve each target before testing |
| `config_editing_enabled` | `false` | Prevent model from editing Burp config |
| `redact_sensitive_headers` | `true` | Strip sensitive headers before model sees them |
| `exclude_cookies` | `true` | Never send cookies to cloud models |
| `exclude_bearer_tokens` | `true` | Never send bearer tokens to cloud models |

## Available MCP Tools

### Read-Only (L0 — Passive)

| Tool | Description |
|------|-------------|
| `proxy.history` | View HTTP request/response history from Burp proxy |
| `target.scope` | View and manage target scope rules |
| `sitemap` | View URLs discovered by Burp |
| `issue.list` | View scanner-identified issues |

### State-Changing L1 (Low Impact)

| Tool | Description |
|------|-------------|
| `repeater.send` | Send a single HTTP request through Repeater |
| `proxy.intercept` | Toggle proxy interception on/off |

### State-Changing L2 (Requires Approval)

| Tool | Description |
|------|-------------|
| `intruder.start` | Run automated attacks against parameters |
| `scanner.start` | Start active vulnerability scanning |
| `spider.start` | Crawl target for content discovery |

## Usage Workflow

### 1. Route Traffic Through Burp

**HTTPS with Python (recommended):**
```python
import urllib.request, ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

proxy = urllib.request.ProxyHandler({"https": "http://127.0.0.1:8080"})
opener = urllib.request.build_opener(proxy, urllib.request.HTTPSHandler(context=ctx))
urllib.request.install_opener(opener)

# All subsequent requests go through Burp
resp = urllib.request.urlopen("https://target.com/")
```

**curl:**
```bash
# HTTP (no SSL issues)
curl --proxy http://127.0.0.1:8080 http://target.com/

# HTTPS (needs Burp CA certificate or -k)
curl --proxy http://127.0.0.1:8080 --proxy-insecure https://target.com/
```

### 2. Use MCP Tools via Claude Code

Once the `.mcp.json` is configured and the session is loaded, the Burp tools
are available as standard MCP tools:

```
User: "Show me the Burp proxy history for the last 20 requests"
User: "Spider https://campaigns.manypets.com/"
User: "Send this request through Repeater: POST /api/login with body {...}"
User: "Start active scan on https://campaigns.manypets.com/admin/login"
User: "What's in the Burp sitemap?"
```

### 3. Use MCP via JSON-RPC (Debug/Testing)

```bash
# Get a session
SESSION=$(curl -s http://127.0.0.1:9876/ | grep -oP 'sessionId=\K[a-f0-9-]+')

# List available tools
curl -X POST "http://127.0.0.1:9876/?sessionId=$SESSION" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'

# Call a tool
curl -X POST "http://127.0.0.1:9876/?sessionId=$SESSION" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"proxy.history","arguments":{"limit":20}},"id":2}'
```

Responses arrive through the SSE stream. Use a proper SSE client (not curl)
for production use — Claude Code handles this automatically.

## Troubleshooting

### MCP server not responding
```bash
# Check process
pgrep -f burp

# Check port
curl http://127.0.0.1:9876/

# Restart Burp and re-enable the MCP extension
```

### SSE returns 404
The MCP SSE endpoint is at the **root path** (`/`), not `/sse`. Verify:
```bash
curl http://127.0.0.1:9876/
# Should return: event: endpoint \n data: ?sessionId=...
```

### Proxy SSL errors
Burp generates a self-signed CA certificate. Export it from Burp
(**Proxy** → **Options** → **Import/Export CA certificate**) and trust it
on your system, or configure your HTTP client to skip verification
(only for local testing).

### Tools not appearing in Claude Code
- Verify `.mcp.json` is in the project root or `~/.claude/mcp.json`
- Restart Claude Code session
- Check `claude mcp list` for the `burp` server

## Reference

- Source code: `src/hackbot/mcp/burp.py`
- Configuration: `.mcp.json` (project root)
- MCP server: `http://127.0.0.1:9876/`
- Burp proxy: `http://127.0.0.1:8080/`
- PortSwigger MCP Extension: [GitHub](https://github.com/PortSwigger/mcp-server)
