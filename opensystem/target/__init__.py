"""OpenSystem target abstraction."""

from .http_site import HttpSiteTarget
from .interface import (
    AdapterCapabilityError,
    Capability,
    TargetAdapter,
    adapter_capability,
    adapter_supports,
)
from .registry import TargetRegistry, register_target

__all__ = [
    "AdapterCapabilityError",
    "Capability",
    "HttpSiteTarget",
    "TargetAdapter",
    "TargetRegistry",
    "adapter_capability",
    "adapter_supports",
    "register_target",
]
