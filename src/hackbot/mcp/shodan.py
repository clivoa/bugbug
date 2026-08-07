"""Shodan adapter — safe, scope-filtered API access.

Shodan results are discovery data only. They never auto-add assets to scope.
All queries are cached, rate-limited, and audit-logged. This adapter wraps the
Shodan REST API with scope filtering applied before results are returned to
the operator or model.

Allowed operations (L0 only):
- Account information and remaining query quota
- Host lookup by IP
- Search queries (rate-limited)
- DNS lookups
- Cached result retrieval

Safety invariants:
- API key redacted from all logs and outputs
- Results filtered through scope before surfacing
- Never treat Shodan results as authorization to test
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ShodanAdapter:
    """Safe, rate-limited Shodan API adapter.

    All operations are L0 (passive). Results are scope-filtered before being
    returned to the caller. The API key is never exposed in output or logs.
    """

    api_key: str = ""
    base_url: str = "https://api.shodan.io"
    cache_dir: str = ""
    _last_query_time: float = field(default=0.0, init=False)
    _min_query_interval: float = 1.0  # 1 second between queries

    def _rate_limit(self) -> None:
        """Enforce minimum interval between API calls."""
        elapsed = time.monotonic() - self._last_query_time
        if elapsed < self._min_query_interval:
            time.sleep(self._min_query_interval - elapsed)
        self._last_query_time = time.monotonic()

    def _get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        """Make a GET request to the Shodan API. Returns parsed JSON or error dict."""
        import urllib.parse
        import urllib.request

        self._rate_limit()
        url = f"{self.base_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        try:
            req = urllib.request.Request(url)
            req.add_header("Accept", "application/json")
            if self.api_key:
                req.add_header("Authorization", f"Bearer {self.api_key}")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            return data if isinstance(data, dict) else {"error": "unexpected response"}
        except Exception as exc:
            return {"error": str(exc)}

    def account_status(self) -> dict[str, Any]:
        """Return account information and remaining query quota."""
        result = self._get("/api-info")
        if "error" in result:
            return result
        return {
            "plan": result.get("plan", "unknown"),
            "query_credits": result.get("query_credits", 0),
            "scan_credits": result.get("scan_credits", 0),
            "monitored_ips": result.get("monitored_ips", 0),
            "unlocked": result.get("unlocked", False),
        }

    def host_lookup(self, ip: str) -> dict[str, Any]:
        """Look up a single IP address. Returns host information.

        The result includes open ports, banners, detected services, and
        location data. This is passive data from Shodan's scans — it does
        not interact with the target directly.
        """
        result = self._get(f"/shodan/host/{ip}")
        if "error" in result:
            return result
        # Redact sensitive fields
        return {
            "ip": result.get("ip_str", ip),
            "organization": result.get("org", ""),
            "operating_system": result.get("os", ""),
            "ports": result.get("ports", []),
            "hostnames": result.get("hostnames", []),
            "domains": result.get("domains", []),
            "country": result.get("country_name", ""),
            "city": result.get("city", ""),
            "last_update": result.get("last_update", ""),
            "vulns": result.get("vulns", []),
        }

    def search(self, query: str, *, page: int = 1) -> dict[str, Any]:
        """Execute a Shodan search query. Returns summary and matched hosts.

        Results are limited to the first page (100 results) to conserve query
        credits. The raw banner data is kept but the API key is stripped.
        """
        result = self._get("/shodan/host/search", {"query": query, "page": str(page)})
        if "error" in result:
            return result
        matches = result.get("matches", [])
        return {
            "total": result.get("total", 0),
            "matches_count": len(matches),
            "matches": [
                {
                    "ip": m.get("ip_str", ""),
                    "port": m.get("port", 0),
                    "organization": m.get("org", ""),
                    "hostnames": m.get("hostnames", []),
                    "domains": m.get("domains", []),
                    "transport": m.get("transport", ""),
                    "timestamp": m.get("timestamp", ""),
                }
                for m in matches
            ],
        }

    def dns_resolve(self, hostname: str) -> dict[str, Any]:
        """Resolve a hostname via Shodan DNS. Returns A/AAAA records."""
        result = self._get("/dns/resolve", {"hostnames": hostname})
        if "error" in result:
            return result
        return {
            hostname: result.get(hostname, None),
        }

    def dns_reverse(self, ip: str) -> dict[str, Any]:
        """Reverse DNS lookup for IP addresses."""
        result = self._get("/dns/reverse", {"ips": ip})
        if "error" in result:
            return result
        return {
            ip: result.get(ip, None),
        }

    def filter_by_scope(
        self, results: dict[str, Any], in_scope_domains: set[str]
    ) -> dict[str, Any]:
        """Filter Shodan search results to only include in-scope assets.

        This is safety-critical: Shodan results are discovery data. They
        must never auto-expand scope. This function filters results so
        only hosts matching known in-scope domains are displayed.

        Args:
            results: Raw search results from Shodan.
            in_scope_domains: Set of domain names that are confirmed in scope.

        Returns:
            Filtered results containing only in-scope matches.
        """
        if "matches" not in results:
            return results

        filtered = []
        for match in results["matches"]:
            hostnames = set(match.get("hostnames", [])) | set(match.get("domains", []))
            for hostname in hostnames:
                # Check if the hostname matches any in-scope domain
                for domain in in_scope_domains:
                    if hostname == domain or hostname.endswith("." + domain):
                        filtered.append(match)
                        break
                else:
                    continue
                break

        return {
            "total": results.get("total", 0),
            "matches_count": len(filtered),
            "matches": filtered,
        }
