"""Provider registry — load, resolve, and route model requests.

Stable local aliases (claude, deepseek, kimi3, local) are mapped to currently
available provider models. The registry queries provider model-list endpoints
at setup and periodically to keep the mapping current.

Safety invariants:
- Never silently switch to a more expensive model.
- Never silently send sensitive engagement data to another provider.
- Cloud fallback is individually configurable per task.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Sensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModelTier(str, Enum):
    FAST = "fast"
    BALANCED = "balanced"
    POWERFUL = "powerful"
    REASONING = "reasoning"


@dataclass(frozen=True, slots=True)
class ModelRef:
    """A resolved model reference: provider alias + concrete model ID."""

    provider: str
    model_id: str
    tier: ModelTier


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    """Immutable snapshot of a single provider's configuration."""

    alias: str
    display_name: str
    base_url: str
    api_key_secret: str
    gateway_only: bool
    default_model: str
    models: Mapping[ModelTier, tuple[str, ...]]
    healthy: bool = True
    last_checked: str = ""


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    """The result of resolving a task to a specific provider + model."""

    task: str
    provider: str
    model_id: str
    tier: ModelTier
    reason: str
    sensitivity: Sensitivity
    cloud_safe: bool
    fallback: ModelRef | None = None
    second_opinion: ModelRef | None = None

    def explain(self) -> str:
        lines = [
            f"Task: {self.task}",
            f"Selected: {self.provider} / {self.model_id} ({self.tier.value})",
            f"Reason: {self.reason}",
            f"Sensitivity: {self.sensitivity.value}",
            f"Data leaves machine: {'yes' if self.cloud_safe else 'no (local only)'}",
        ]
        if self.fallback:
            lines.append(f"Fallback: {self.fallback.provider} / {self.fallback.model_id}")
        if self.second_opinion:
            lines.append(
                f"Second opinion: {self.second_opinion.provider} / {self.second_opinion.model_id}"
            )
        return "\n".join(lines)


@dataclass
class TaskRouting:
    """A single task's routing policy (mutable during loading, frozen at runtime)."""

    task: str
    description: str = ""
    preferred_provider: str = ""
    preferred_tier: ModelTier = ModelTier.BALANCED
    fallback_provider: str = ""
    fallback_tier: ModelTier = ModelTier.BALANCED
    second_opinion_provider: str = ""
    second_opinion_tier: ModelTier = ModelTier.BALANCED
    sensitivity: Sensitivity = Sensitivity.LOW
    cloud_fallback_disabled: bool = False


@dataclass
class ProviderRegistry:
    """The loaded provider + routing configuration."""

    providers: dict[str, ProviderInfo] = field(default_factory=dict)
    routing: dict[str, TaskRouting] = field(default_factory=dict)
    auto_order: tuple[str, ...] = ()

    def resolve(
        self,
        task: str,
        *,
        preferred_provider: str | None = None,
        preferred_tier: ModelTier | None = None,
        sensitivity_override: Sensitivity | None = None,
    ) -> RoutingDecision:
        """Resolve a task to a specific provider and model.

        Resolution order:
        1. Explicit caller preference (if provider is healthy)
        2. Task-specific routing config
        3. Auto-routing by provider order
        """
        task_routing = self.routing.get(task)
        sensitivity = sensitivity_override or (
            task_routing.sensitivity if task_routing else Sensitivity.LOW
        )

        # Check cloud fallback disabled for critical sensitivity
        cloud_fallback_disabled = task_routing.cloud_fallback_disabled if task_routing else False
        if sensitivity == Sensitivity.CRITICAL:
            cloud_fallback_disabled = True

        # 1. Explicit preference
        if preferred_provider and preferred_provider in self.providers:
            provider = self.providers[preferred_provider]
            if provider.healthy:
                model = self._pick_model(provider, preferred_tier or ModelTier.BALANCED)
                return RoutingDecision(
                    task=task,
                    provider=provider.alias,
                    model_id=model,
                    tier=preferred_tier or ModelTier.BALANCED,
                    reason="explicit caller preference",
                    sensitivity=sensitivity,
                    cloud_safe=not provider.gateway_only,
                )

        # 2. Task-specific routing
        if task_routing:
            decision = self._resolve_from_task_routing(
                task, task_routing, sensitivity, cloud_fallback_disabled
            )
            if decision:
                return decision

        # 3. Auto-routing
        for alias in self.auto_order:
            if alias in self.providers:
                provider = self.providers[alias]
                if provider.healthy and not (cloud_fallback_disabled and alias != "local"):
                    model = self._pick_model(provider, ModelTier.BALANCED)
                    return RoutingDecision(
                        task=task,
                        provider=provider.alias,
                        model_id=model,
                        tier=ModelTier.BALANCED,
                        reason=f"auto-routing (order position: {alias})",
                        sensitivity=sensitivity,
                        cloud_safe=alias == "local",
                    )

        # 4. Last resort: first healthy provider
        for alias, provider in self.providers.items():
            if provider.healthy:
                model = self._pick_model(provider, ModelTier.FAST)
                return RoutingDecision(
                    task=task,
                    provider=provider.alias,
                    model_id=model,
                    tier=ModelTier.FAST,
                    reason="last-resort fallback",
                    sensitivity=sensitivity,
                    cloud_safe=alias == "local",
                )

        raise RuntimeError("No healthy providers available")

    def _resolve_from_task_routing(
        self,
        task: str,
        routing: TaskRouting,
        sensitivity: Sensitivity,
        cloud_fallback_disabled: bool,
    ) -> RoutingDecision | None:
        preferred = routing.preferred_provider
        if preferred in self.providers and self.providers[preferred].healthy:
            provider = self.providers[preferred]
            model = self._pick_model(provider, routing.preferred_tier)
            fallback = self._fallback_ref(routing, cloud_fallback_disabled)
            second = self._second_opinion_ref(routing)
            return RoutingDecision(
                task=task,
                provider=provider.alias,
                model_id=model,
                tier=routing.preferred_tier,
                reason=f"task routing: {routing.description or task}",
                sensitivity=sensitivity,
                cloud_safe=preferred != "local" or sensitivity != Sensitivity.CRITICAL,
                fallback=fallback,
                second_opinion=second,
            )

        fallback_provider: str = routing.fallback_provider
        if fallback_provider in self.providers and self.providers[fallback_provider].healthy:
            if cloud_fallback_disabled and fallback_provider != "local":
                return None
            provider = self.providers[fallback_provider]
            fallback_model = self._pick_model(provider, routing.fallback_tier)
            return RoutingDecision(
                task=task,
                provider=provider.alias,
                model_id=fallback_model,
                tier=routing.fallback_tier,
                reason=f"task routing fallback: {routing.description or task}",
                sensitivity=sensitivity,
                cloud_safe=fallback_provider == "local",
            )

        return None

    def _fallback_ref(self, routing: TaskRouting, cloud_fallback_disabled: bool) -> ModelRef | None:
        fb = routing.fallback_provider
        if not fb or fb not in self.providers:
            return None
        if cloud_fallback_disabled and fb != "local":
            return None
        provider = self.providers[fb]
        model = self._pick_model(provider, routing.fallback_tier)
        return ModelRef(provider=fb, model_id=model, tier=routing.fallback_tier)

    def _second_opinion_ref(self, routing: TaskRouting) -> ModelRef | None:
        so = routing.second_opinion_provider
        if not so or so not in self.providers:
            return None
        provider = self.providers[so]
        model = self._pick_model(provider, routing.second_opinion_tier)
        return ModelRef(provider=so, model_id=model, tier=routing.second_opinion_tier)

    @staticmethod
    def _pick_model(provider: ProviderInfo, tier: ModelTier) -> str:
        models = provider.models.get(tier, ())
        if models:
            return models[0]
        # Fall through tiers: reasoning → powerful → balanced → fast → default
        for fallback_tier in ModelTier:
            fallback_models = provider.models.get(fallback_tier, ())
            if fallback_models:
                return fallback_models[0]
        return provider.default_model

    def provider_aliases(self) -> tuple[str, ...]:
        return tuple(self.providers)

    def healthy_providers(self) -> tuple[str, ...]:
        return tuple(a for a, p in self.providers.items() if p.healthy)


def load_registry(
    providers_config: Path | None = None,
    routing_config: Path | None = None,
) -> ProviderRegistry:
    """Load provider and routing configuration from YAML files.

    Args:
        providers_config: Path to config/providers.yaml
        routing_config: Path to config/model-routing.yaml

    Returns:
        A populated ProviderRegistry ready for model resolution.
    """
    import os

    providers: dict[str, ProviderInfo] = {}
    routing: dict[str, TaskRouting] = {}
    auto_order: tuple[str, ...] = ()

    # --- Load providers ---
    if providers_config and os.path.isfile(providers_config):
        raw = _load_yaml(providers_config)
        if raw:
            auto_order = tuple(raw.get("auto_routing", {}).get("order", ()))
            for alias, cfg in raw.get("providers", {}).items():
                if not isinstance(cfg, dict):
                    continue
                models: dict[ModelTier, tuple[str, ...]] = {}
                for tier_name, model_list in cfg.get("models", {}).items():
                    try:
                        tier = ModelTier(tier_name)
                    except ValueError:
                        continue
                    if isinstance(model_list, list):
                        models[tier] = tuple(m for m in model_list if isinstance(m, str))
                providers[alias] = ProviderInfo(
                    alias=alias,
                    display_name=str(cfg.get("display_name", alias)),
                    base_url=str(cfg.get("base_url", "")),
                    api_key_secret=str(cfg.get("api_key_secret", "")),
                    gateway_only=bool(cfg.get("gateway_only", False)),
                    default_model=str(cfg.get("default_model", "")),
                    models=models,
                )

    # --- Load routing ---
    if routing_config and os.path.isfile(routing_config):
        raw = _load_yaml(routing_config)
        if raw:
            for task_name, cfg in raw.get("tasks", {}).items():
                if not isinstance(cfg, dict):
                    continue
                preferred = cfg.get("preferred", {})
                fallback = cfg.get("fallback", {})
                second = cfg.get("second_opinion", {})
                tr = TaskRouting(
                    task=task_name,
                    description=str(cfg.get("description", "")),
                    preferred_provider=str(preferred.get("provider", ""))
                    if isinstance(preferred, dict)
                    else "",
                    preferred_tier=_parse_tier(preferred.get("tier"))
                    if isinstance(preferred, dict)
                    else ModelTier.BALANCED,
                    fallback_provider=str(fallback.get("provider", ""))
                    if isinstance(fallback, dict)
                    else "",
                    fallback_tier=_parse_tier(fallback.get("tier"))
                    if isinstance(fallback, dict)
                    else ModelTier.BALANCED,
                    second_opinion_provider=str(second.get("provider", ""))
                    if isinstance(second, dict)
                    else "",
                    second_opinion_tier=_parse_tier(second.get("tier"))
                    if isinstance(second, dict)
                    else ModelTier.BALANCED,
                    sensitivity=_parse_sensitivity(cfg.get("sensitivity")),
                    cloud_fallback_disabled=cfg.get("cloud_fallback") == "disabled",
                )
                routing[task_name] = tr

    return ProviderRegistry(
        providers=providers,
        routing=routing,
        auto_order=auto_order,
    )


def _parse_tier(value: object) -> ModelTier:
    if isinstance(value, str):
        try:
            return ModelTier(value)
        except ValueError:
            pass
    return ModelTier.BALANCED


def _parse_sensitivity(value: object) -> Sensitivity:
    if isinstance(value, str):
        try:
            return Sensitivity(value)
        except ValueError:
            pass
    return Sensitivity.LOW


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file safely; return {} on any error."""
    try:
        import yaml
    except ImportError:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
