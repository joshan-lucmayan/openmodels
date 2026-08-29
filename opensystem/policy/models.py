"""Policy and authorization layer (Phase 11).

OpenSystem is attacker-oriented, but its deployment layer must know what it is
authorized to do. This layer is deliberately kept separate from the adversarial
reasoning engine — attack strategies never embed authorization assumptions.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from opensystem.models import Target, new_id, utcnow


class Operation(str, Enum):
    """Operations an OpenSystem instance may perform."""

    OBSERVE = "OBSERVE"
    TEST = "TEST"
    RESET = "RESET"
    DESTRUCTIVE = "DESTRUCTIVE"
    AUTHENTICATED = "AUTHENTICATED"
    PROOF_SESSION = "PROOF_SESSION"


class StopReason(str, Enum):
    MAX_ROUNDS = "MAX_ROUNDS"
    POLICY_STOP = "POLICY_STOP"
    ALL_HYPOTHESES_TESTED = "ALL_HYPOTHESES_TESTED"
    NO_MORE_HYPOTHESES = "NO_MORE_HYPOTHESES"
    MANUAL = "MANUAL"
    ERROR = "ERROR"


class Policy(BaseModel):
    """The authorization boundary for a research session."""

    id: str = Field(default_factory=new_id)
    target_name: str = "*"
    environment: str = "local-mock"
    allowed_operations: list[Operation] = Field(
        default_factory=lambda: [
            Operation.OBSERVE,
            Operation.TEST,
            Operation.RESET,
        ]
    )
    max_rounds: int = 10
    max_experiments: int = 100
    allowed_credentials: list[str] = Field(default_factory=list)
    destructive_actions_allowed: bool = False
    stop_on_finding: bool = False
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())

    def allows(self, operation: Operation) -> bool:
        return operation in self.allowed_operations

    def __str__(self) -> str:
        ops = ", ".join(o.value for o in self.allowed_operations)
        return (
            f"Policy[{self.target_name}] env={self.environment} "
            f"ops=[{ops}] max_rounds={self.max_rounds} "
            f"destructive={self.destructive_actions_allowed}"
        )
