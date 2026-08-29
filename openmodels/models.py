"""Structured, persistable entities used across OpenModels.

These are the first-class objects of the research process. Nothing in
OpenModels represents the research process as unstructured text: every step —
hypothesis, observation, experiment, result, evidence, finding, defense,
regression, knowledge, evolution event — is an explicit model that can be
persisted to the knowledge store and reasoned over.
"""

from __future__ import annotations

import datetime
import uuid
from enum import Enum

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #

class TestOutcome(str, Enum):
    """Result of executing a test against a target."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


class HypothesisStatus(str, Enum):
    PROPOSED = "PROPOSED"
    ACTIVE = "ACTIVE"
    TESTED = "TESTED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SUPERSEDED = "SUPERSEDED"


class FindingStatus(str, Enum):
    """Finding lifecycle (Phase 8)."""

    DISCOVERED = "DISCOVERED"
    CONFIRMED = "CONFIRMED"
    DOCUMENTED = "DOCUMENTED"
    MITIGATION = "MITIGATION"
    VERIFICATION = "VERIFICATION"
    CLOSED = "CLOSED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EvidenceKind(str, Enum):
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"
    LOG = "LOG"
    OUTPUT = "OUTPUT"
    STATE = "STATE"
    ARTIFACT = "ARTIFACT"
    OBSERVATION = "OBSERVATION"


class KnowledgeKind(str, Enum):
    ASSUMPTION = "ASSUMPTION"
    ATTACK_STRATEGY = "ATTACK_STRATEGY"
    FAILED_STRATEGY = "FAILED_STRATEGY"
    SUCCESSFUL_STRATEGY = "SUCCESSFUL_STRATEGY"
    DEFENSE = "DEFENSE"
    TARGET_CHANGE = "TARGET_CHANGE"
    PATTERN = "PATTERN"


class EvolutionTrigger(str, Enum):
    ATTACK_SUCCESS = "ATTACK_SUCCESS"
    ATTACK_FAILURE = "ATTACK_FAILURE"
    DEFENSE_APPLIED = "DEFENSE_APPLIED"
    TARGET_CHANGE = "TARGET_CHANGE"
    REGRESSION = "REGRESSION"
    MANUAL = "MANUAL"


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #

def new_id() -> str:
    return uuid.uuid4().hex[:16]


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# --------------------------------------------------------------------------- #
# Target
# --------------------------------------------------------------------------- #

class Target(BaseModel):
    """A model of the target system under adversarial evaluation."""

    id: str = Field(default_factory=new_id)
    name: str
    kind: str = "generic"
    adapter: str = "mock"
    description: str = ""
    version: str = "0.0.0"
    assets: list[str] = Field(default_factory=list)
    interfaces: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    rules: dict = Field(default_factory=dict)
    created_at: datetime.datetime = Field(default_factory=utcnow)
    updated_at: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Observation
# --------------------------------------------------------------------------- #

class Observation(BaseModel):
    """Something observed about the target."""

    id: str = Field(default_factory=new_id)
    target_id: str
    interface: str
    data: dict = Field(default_factory=dict)
    source: str
    timestamp: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Hypothesis
# --------------------------------------------------------------------------- #

class Hypothesis(BaseModel):
    """A testable claim about a potential weakness."""

    id: str = Field(default_factory=new_id)
    target_id: str
    statement: str
    assumption: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    parent_id: str | None = None
    origin: str = "manual"
    confidence: float = 0.5
    created_at: datetime.datetime = Field(default_factory=utcnow)
    updated_at: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Test / Experiment
# --------------------------------------------------------------------------- #

class TestSpec(BaseModel):
    """A concrete, executable test derived from a hypothesis."""

    name: str
    description: str = ""
    parameters: dict = Field(default_factory=dict)
    expected_outcome: TestOutcome = TestOutcome.SUCCESS


class TestResult(BaseModel):
    """Outcome of executing a test against the target."""

    outcome: TestOutcome
    observed_result: str = ""
    detail: dict = Field(default_factory=dict)
    evidence: list["Evidence"] = Field(default_factory=list)


class Experiment(BaseModel):
    """A single test of a hypothesis, fully recorded (Phase 7).

    Failed experiments MUST be retained: a failed attack is valuable
    information.
    """

    id: str = Field(default_factory=new_id)
    hypothesis_id: str
    target_id: str
    openmodels_version: str
    test: TestSpec
    expected_result: str = ""
    observed_result: str = ""
    outcome: TestOutcome = TestOutcome.INCONCLUSIVE
    conclusion: str = ""
    next_hypothesis_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    started_at: datetime.datetime = Field(default_factory=utcnow)
    completed_at: datetime.datetime | None = None


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #

class Evidence(BaseModel):
    """Evidence collected in support of an experiment."""

    id: str = Field(default_factory=new_id)
    experiment_id: str | None = None
    kind: EvidenceKind = EvidenceKind.OBSERVATION
    data: dict = Field(default_factory=dict)
    reference: str = ""
    captured_at: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #

class Finding(BaseModel):
    """A confirmed weakness, with a full lifecycle (Phase 8)."""

    id: str = Field(default_factory=new_id)
    target_id: str
    hypothesis_id: str | None = None
    severity: Severity = Severity.MEDIUM
    affected_component: str = ""
    attack_hypothesis: str = ""
    observed_behavior: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    impact: str = ""
    reproduction: str = ""
    recommended_mitigation: str = ""
    verification_status: FindingStatus = FindingStatus.DISCOVERED
    created_at: datetime.datetime = Field(default_factory=utcnow)
    updated_at: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Defense / Regression
# --------------------------------------------------------------------------- #

class Defense(BaseModel):
    """A mitigation applied by the defender."""

    id: str = Field(default_factory=new_id)
    finding_id: str
    description: str
    verification_status: FindingStatus = FindingStatus.MITIGATION
    applied_at: datetime.datetime = Field(default_factory=utcnow)


class Regression(BaseModel):
    """A regression test proving a previously-found weakness stays fixed."""

    id: str = Field(default_factory=new_id)
    defense_id: str
    hypothesis_id: str
    target_id: str
    outcome: TestOutcome
    detail: str = ""
    created_at: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Knowledge
# --------------------------------------------------------------------------- #

class Knowledge(BaseModel):
    """A persistent piece of learned knowledge."""

    id: str = Field(default_factory=new_id)
    kind: KnowledgeKind
    content: str
    target_id: str | None = None
    provenance: str = ""
    created_at: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Evolution
# --------------------------------------------------------------------------- #

class EvolutionEvent(BaseModel):
    """An auditable evolution step with reason and provenance (Phase 9)."""

    id: str = Field(default_factory=new_id)
    trigger: EvolutionTrigger
    reason: str
    from_hypothesis_id: str | None = None
    to_hypothesis_id: str | None = None
    provenance: str = ""
    created_at: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

class ResearchReport(BaseModel):
    """Aggregate result of a research session (evidence-based status)."""

    target_id: str
    openmodels_version: str
    rounds_executed: int = 0
    hypotheses_formed: int = 0
    experiments_run: int = 0
    successful_tests: int = 0
    failed_tests: int = 0
    blocked_tests: int = 0
    inconclusive_tests: int = 0
    findings_created: int = 0
    open_findings: int = 0
    attack_classes_attempted: set[str] = Field(default_factory=set)
    attack_classes_untested: set[str] = Field(default_factory=set)
    stopped_reason: str = ""
