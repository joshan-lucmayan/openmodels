"""OpenSystem target abstraction."""

from .interface import TargetAdapter, TargetDescription
from .mock import MockTarget
from .registry import TargetRegistry, register_target

__all__ = [
    "TargetAdapter",
    "TargetDescription",
    "MockTarget",
    "TargetRegistry",
    "register_target",
]
