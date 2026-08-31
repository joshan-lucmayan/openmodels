"""Structured, persistable entities used across OpenSystem.

These are the first-class objects of the research process. Nothing in
OpenSystem represents the research process as unstructured text: every step —
hypothesis, observation, experiment, result, evidence, finding, knowledge,
evolution event — is an explicit model that can be persisted to the knowledge
store and reasoned over.
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
    TARGET_CHANGE = "TARGET_CHANGE"
    PATTERN = "PATTERN"


class EvolutionTrigger(str, Enum):
    ATTACK_SUCCESS = "ATTACK_SUCCESS"
    ATTACK_FAILURE = "ATTACK_FAILURE"
    TARGET_CHANGE = "TARGET_CHANGE"
    MANUAL = "MANUAL"


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #

def new_id() -> str:
    return uuid.uuid4().hex[:16]


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


# --------------------------------------------------------------------------- #
# Target
# --------------------------------------------------------------------------- #

class Target(BaseModel):
    """A model of the target system under adversarial evaluation.

    ``environment`` and ``scope`` are declared by the adapter and consulted
    by the policy layer when it restricts those dimensions; they are never
    inferred from client-supplied data.
    """

    id: str = Field(default_factory=new_id)
    name: str
    kind: str = "generic"
    adapter: str = "http"
    description: str = ""
    version: str = "0.0.0"
    assets: list[str] = Field(default_factory=list)
    interfaces: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    rules: dict = Field(default_factory=dict)
    environment: str = ""
    scope: str = ""
    created_at: datetime.datetime = Field(default_factory=utcnow)
    updated_at: datetime.datetime = Field(default_factory=utcnow)


class TargetConfig(BaseModel):
    """Deployment-time configuration describing an authorized target.

    The core engine does NOT assume every target is a website. This config
    describes what the target is, what is authorized, and how a session may
    behave. Policy/authorization lives here and in the policy layer — never
    in attack strategies.
    """

    name: str
    target_type: str = "generic"
    adapter: str = "http"
    organization: str = ""
    environment: str = "development"
    description: str = ""
    authorized_scope: str = ""
    available_interfaces: list[str] = Field(default_factory=list)
    test_credentials: list[str] = Field(default_factory=list)
    protected_resources: list[str] = Field(default_factory=list)
    testing_policy: dict = Field(default_factory=dict)
    time_window: str = ""
    emergency_stop: bool = False
    url: str = ""
    """Base URL for live network targets (adapter=http)."""
    allow_insecure_tls: bool = False
    """Disable TLS verification (self-signed certs in test environments)."""
    created_at: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Observations
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
    evidence: list[Evidence] = Field(default_factory=list)


class Experiment(BaseModel):
    """A single test of a hypothesis, fully recorded (Phase 7).

    Failed experiments MUST be retained: a failed attack is valuable
    information.
    """

    id: str = Field(default_factory=new_id)
    hypothesis_id: str
    target_id: str
    opensystem_version: str
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
    """A confirmed weakness, with a full lifecycle (Phase 8).

    ``affected_component`` is a human-readable display string only — it is
    never the canonical source for resolving entities.
    """

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
# Journal
# --------------------------------------------------------------------------- #

class JournalEntry(BaseModel):
    """A human-readable record of one attack performed by OpenSystem.

    Combines the documented methodology for the attack type with the
    runtime specifics (target, parameters, observed result, evidence). The
    journal is the complete, auditable account of what was tested, how, and
    what the target returned.
    """

    id: str = Field(default_factory=new_id)
    target_id: str
    target_url: str = ""
    attack_key: str = ""
    attack_name: str = ""
    family: str = ""
    outcome: TestOutcome = TestOutcome.INCONCLUSIVE
    summary: str = ""
    how_it_was_done: str = ""
    observed_result: str = ""
    detail: dict | str = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    hypothesis_id: str | None = None
    experiment_id: str | None = None
    created_at: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

class ResearchReport(BaseModel):
    """Aggregate result of a research session (evidence-based status)."""

    target_id: str
    opensystem_version: str
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
    stopped_reason: str = ""
