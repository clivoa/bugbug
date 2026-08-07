"""Local LLM gateway — LiteLLM or equivalent, listening only on loopback.

The gateway is the single point through which all model requests flow. It:
- Enforces loopback-only binding (127.0.0.1).
- Routes to the configured provider based on the task routing policy.
- Never exposes API keys to the model context.
- Provides health checks and model-list caching.
"""

from hackbot.gateway.client import GatewayClient, GatewayConfig

__all__ = ["GatewayClient", "GatewayConfig"]
