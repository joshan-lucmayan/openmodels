"""OpenSystem target abstraction."""

from .interface import (
    AdapterCapabilityError,
    Capability,
    TargetAdapter,
    adapter_capability,
    adapter_supports,
)
from .mock import MockTarget
from .registry import TargetRegistry, register_target

__all__ = [
    "AdapterCapabilityError",
    "Capability",
    "MockTarget",
    "TargetAdapter",
    "TargetRegistry",
    "adapter_capability",
    "adapter_supports",
    "register_target",
]
