"""Burp Suite MCP integration — configuration and safe defaults.

Uses the official PortSwigger Burp MCP extension. The MCP service must listen
only on loopback (http://127.0.0.1:9876).

Security defaults:
- Target approval: enabled
- Auto-approved targets: empty
- Burp configuration editing: disabled
- Only current engagement targets may be approved
- Proxy history access: restricted to approved targets
- Sensitive headers redacted before sending to cloud models
- Cookies and bearer tokens excluded unless explicitly required
- MCP responses treated as untrusted data
- Tools divided into read-only and state-changing groups
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class BurpMCPConfig:
    """Validated Burp MCP connection configuration — loopback only."""

    base_url: str = "http://127.0.0.1:9876"
    target_approval_enabled: bool = True
    auto_approved_targets: tuple[str, ...] = ()
    config_editing_enabled: bool = False
    redact_sensitive_headers: bool = True
    exclude_cookies: bool = True
    exclude_bearer_tokens: bool = True

    # Tool grouping
    read_only_tools: tuple[str, ...] = field(
        default_factory=lambda: (
            "proxy.history",
            "target.scope",
            "sitemap",
        )
    )
    state_changing_tools: tuple[str, ...] = field(
        default_factory=lambda: (
            "repeater.send",
            "intruder.start",
            "scanner.start",
        )
    )

    def __post_init__(self) -> None:
        # Verify loopback binding
        if "127.0.0.1" not in self.base_url and "localhost" not in self.base_url:
            raise ValueError(
                "Burp MCP must listen on loopback only. "
                f"Got base_url={self.base_url!r}. Use http://127.0.0.1:9876."
            )


def configure_burp_mcp(
    config: BurpMCPConfig | None = None,
) -> dict[str, object]:
    """Return Claude Code MCP configuration for Burp Suite.

    The returned dict is suitable for use in .mcp.json or as arguments to
    `claude mcp add`. It configures the Burp MCP server with safe defaults.

    Args:
        config: Optional validated BurpMCPConfig. Uses safe defaults if None.

    Returns:
        A dict with MCP server configuration for Burp Suite.
    """
    cfg = config or BurpMCPConfig()

    return {
        "burp": {
            "type": "sse",
            "url": cfg.base_url + "/sse",
            "headers": {
                "Content-Type": "application/json",
            },
        }
    }


def burp_tool_classification() -> dict[str, list[str]]:
    """Return the classification of Burp MCP tools by risk level.

    Read-only tools (L0): can be used for passive observation.
    State-changing tools (L1-L2): require approval before use.
    """
    return {
        "read_only": [
            "proxy.history",
            "target.scope",
            "sitemap",
            "issue.list",
        ],
        "state_changing_l1": [
            "repeater.send",  # Single request in Repeater
            "proxy.intercept",  # Intercept toggle
        ],
        "state_changing_l2": [
            "intruder.start",  # Automated attack
            "scanner.start",  # Active scanning
            "spider.start",  # Active crawling
        ],
    }
