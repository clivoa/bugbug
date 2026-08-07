"""MCP (Model Context Protocol) integrations.

Supported MCP servers:
- Burp Suite (PortSwigger official MCP extension)
- Shodan (safe adapter with scope filtering)

All MCP servers must listen on loopback (127.0.0.1) only. MCP tool responses are
treated as untrusted data and never interpreted as instructions or scope changes.
"""

from hackbot.mcp.burp import BurpMCPConfig, configure_burp_mcp
from hackbot.mcp.shodan import ShodanAdapter

__all__ = ["BurpMCPConfig", "ShodanAdapter", "configure_burp_mcp"]
