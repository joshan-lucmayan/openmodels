"""Registry for target adapters.

Adapters are registered here and discovered by name. This keeps the core
engine decoupled from concrete adapter implementations: a new adapter (web app,
LLM service, simulation, …) is registered without touching the engine.
"""

from __future__ import annotations

from opensystem.target.http_site import HttpSiteTarget
from opensystem.target.interface import TargetAdapter

_registry: dict[str, type[TargetAdapter]] = {}


def register_target(adapter_cls: type[TargetAdapter]) -> type[TargetAdapter]:
    """Register an adapter class under its ``name`` attribute."""
    name = getattr(adapter_cls, "name", None)
    if not name or not isinstance(name, str):
        raise ValueError(
            f"Adapter {adapter_cls.__name__} must define a 'name' attribute."
        )
    if name in _registry:
        raise ValueError(f"Target adapter '{name}' already registered.")
    _registry[name] = adapter_cls
    return adapter_cls


class TargetRegistry:
    """Lookup and instantiation of target adapters."""

    def __init__(self) -> None:
        self._adapters = _registry

    def names(self) -> list[str]:
        return sorted(self._adapters)

    def get(self, name: str) -> type[TargetAdapter]:
        if name not in self._adapters:
            raise KeyError(
                f"Unknown target adapter '{name}'. "
                f"Available: {', '.join(self.names()) or '(none)'}"
            )
        return self._adapters[name]

    def create(self, name: str, **kwargs) -> TargetAdapter:
        return self.get(name)(**kwargs)


# Register built-in adapters at import time.
register_target(HttpSiteTarget)
