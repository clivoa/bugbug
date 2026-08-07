"""Provider and model management — aliases, resolution, health, and routing.

All provider configuration is read from config/providers.yaml and
config/model-routing.yaml. Secrets are resolved through the OS keychain backend
(never from config files or environment variables).
"""

from hackbot.providers.registry import (
    ModelRef,
    ProviderInfo,
    ProviderRegistry,
    RoutingDecision,
    TaskRouting,
    load_registry,
)

__all__ = [
    "ModelRef",
    "ProviderInfo",
    "ProviderRegistry",
    "RoutingDecision",
    "TaskRouting",
    "load_registry",
]
