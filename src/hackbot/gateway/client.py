"""Gateway client — typed configuration and health-check interface for the local
LLM gateway. The gateway itself (LiteLLM or an equivalent Anthropic-compatible
proxy) runs as a separate process, bound to 127.0.0.1 only.

This module provides:
- GatewayConfig: validated loopback-only connection parameters.
- GatewayClient: health check, model list, and provider status queries.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    """Validated gateway connection configuration — loopback only."""

    base_url: str
    api_key: str = ""
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        # Enforce loopback-only: the gateway must never be exposed on a network
        # interface. Parse the host from the URL and verify it's 127.0.0.1 or
        # localhost (both resolve to loopback).
        host = self._extract_host(self.base_url)
        if not self._is_loopback(host):
            raise ValueError(
                f"Gateway must listen on loopback only, got host: {host!r}. "
                f"Configure base_url to use 127.0.0.1 or localhost."
            )

    @staticmethod
    def _extract_host(url: str) -> str:
        """Extract the host component from a URL string."""
        u = url.strip()
        # Remove scheme
        if "://" in u:
            u = u.split("://", 1)[1]
        # Remove path, query, fragment
        for sep in ("/", "?", "#"):
            if sep in u:
                u = u.split(sep, 1)[0]
        # Remove port
        if ":" in u and not u.startswith("["):
            # Could be IPv6 like [::1]:4000 — handle bracket notation
            if u.startswith("["):
                u = u.split("]", 1)[0] + "]"
            else:
                u = u.rsplit(":", 1)[0]
        # Remove brackets from IPv6 literal
        u = u.strip("[]")
        return u

    @staticmethod
    def _is_loopback(host: str) -> bool:
        """Check if host is a loopback address."""
        if host.lower() in ("localhost", "127.0.0.1", "::1"):
            return True
        try:
            addr = ipaddress.ip_address(host)
            return addr.is_loopback
        except ValueError:
            return False


class GatewayClient:
    """Typed interface to the local LLM gateway.

    All methods are read-only: they query status, list models, and validate
    connectivity. No mutation of gateway state is possible through this client.
    """

    def __init__(self, config: GatewayConfig) -> None:
        self._config = config

    @property
    def base_url(self) -> str:
        return self._config.base_url

    def health(self) -> bool:
        """Check if the gateway is reachable and responding."""
        import urllib.request

        try:
            req = urllib.request.Request(
                f"{self._config.base_url}/health",
                headers={"Authorization": f"Bearer {self._config.api_key}"}
                if self._config.api_key
                else {},
            )
            with urllib.request.urlopen(req, timeout=self._config.timeout_seconds) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return the list of model IDs the gateway currently exposes."""
        import json
        import urllib.request

        try:
            req = urllib.request.Request(
                f"{self._config.base_url}/v1/models",
                headers={"Authorization": f"Bearer {self._config.api_key}"}
                if self._config.api_key
                else {},
            )
            with urllib.request.urlopen(req, timeout=self._config.timeout_seconds) as resp:
                data = json.loads(resp.read().decode())
            if isinstance(data, dict) and "data" in data:
                return [m["id"] for m in data["data"] if isinstance(m, dict) and "id" in m]
            return []
        except Exception:
            return []

    def provider_status(self) -> Mapping[str, Any]:
        """Return per-provider status information from the gateway."""
        import json
        import urllib.request

        try:
            req = urllib.request.Request(
                f"{self._config.base_url}/provider/status",
                headers={"Authorization": f"Bearer {self._config.api_key}"}
                if self._config.api_key
                else {},
            )
            with urllib.request.urlopen(req, timeout=self._config.timeout_seconds) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return {"error": "gateway unreachable"}
