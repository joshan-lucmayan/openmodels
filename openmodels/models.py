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


class ProtectedResourceType(str, Enum):
    """Kinds of protected resources OpenModels can reason about.

    Deliberately generic: the same architecture reasons about paid AI
    inference, paid APIs, premium features, protected data, cloud/compute
    resources, privileged functionality, and more.
    """

    AI_MODEL = "ai_model"
    API = "api"
    DATA = "data"
    COMPUTE = "compute"
    FEATURE = "feature"
    WEB_UI = "web_ui"
    STORAGE = "storage"
    NETWORK = "network"
    SERVICE = "service"


class ActorKind(str, Enum):
    """Kinds of actors that may (or may not) be entitled to a resource.

    An actor's privileges are NEVER assumed from client-supplied values;
    they are declared in the entitlement model and the target decides whether
    to actually enforce them.
    """

    UNAUTHENTICATED = "UNAUTHENTICATED"
    FREE_USER = "FREE_USER"
    PAID_USER = "PAID_USER"
    ORG_MEMBER = "ORG_MEMBER"
    ORG_ADMIN = "ORG_ADMIN"
    API_CLIENT = "API_CLIENT"
    SYSTEM = "SYSTEM"


class EntitlementDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


class InvariantStatus(str, Enum):
    UNTESTED = "UNTESTED"
    PASSED = "PASSED"
    VIOLATED = "VIOLATED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ObjectiveStatus(str, Enum):
    FORMULATED = "FORMULATED"
    ACTIVE = "ACTIVE"
    ACHIEVED = "ACHIEVED"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"


class CampaignStatus(str, Enum):
    CREATED = "CREATED"
    DISCOVERING = "DISCOVERING"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class InvariantOutcome(str, Enum):
    """Outcome of testing a security invariant across one path.

    PASSED  -- the boundary held (forbidden access was denied)
    VIOLATED -- the boundary was crossed (forbidden access succeeded)
    """

    PASSED = "PASSED"
    VIOLATED = "VIOLATED"
    INCONCLUSIVE = "INCONCLUSIVE"


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


class TargetConfig(BaseModel):
    """Deployment-time configuration describing an authorized target.

    The core engine does NOT assume every target is a website. This config
    describes what the target is, what is authorized, and how a session may
    behave. Policy/authorization lives here and in the policy layer — never
    in attack strategies.
    """

    name: str
    target_type: str = "generic"
    adapter: str = "mock"
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
    created_at: datetime.datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Protected resources
# --------------------------------------------------------------------------- #

class ProtectedResource(BaseModel):
    """Something valuable that an actor without entitlement must NOT access.

    The protected resource is the object of the adversarial campaign. The
    engine asks: can an actor not entitled to this resource cause it to be
    accessed, consumed, modified, or disclosed?
    """

    id: str = Field(default_factory=new_id)
    name: str
    resource_type: ProtectedResourceType = ProtectedResourceType.API
    value: str = ""
    description: str = ""
    interfaces: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Actors / entitlements
# --------------------------------------------------------------------------- #

class Actor(BaseModel):
    """An actor that may (or may not) be entitled to protected resources.

    An actor has capabilities and declared entitlements. OpenModels does NOT
    assume the actor's privileges from client-supplied values; it investigates
    whether the target actually enforces the declared boundary.
    """

    id: str = Field(default_factory=new_id)
    name: str
    kind: ActorKind = ActorKind.UNAUTHENTICATED
    description: str = ""
    entitlements: list[str] = Field(default_factory=list)


class Entitlement(BaseModel):
    """A declared entitlement: actor may perform an action on a resource."""

    id: str = Field(default_factory=new_id)
    actor_id: str
    resource_id: str
    action: str = "access"


# --------------------------------------------------------------------------- #
# Security invariants
# --------------------------------------------------------------------------- #

class SecurityInvariant(BaseModel):
    """A security boundary that MUST hold.

    Example:
        "Actor without premium entitlement MUST NOT consume premium inference."

    The invariant is tested across multiple interfaces and states. The engine
    records: INVARIANT → TEST → RESULT.
    """

    id: str = Field(default_factory=new_id)
    actor_id: str
    resource_id: str
    forbidden_action: str = "access"
    statement: str = ""
    status: InvariantStatus = InvariantStatus.UNTESTED


# --------------------------------------------------------------------------- #
# Attack objectives
# --------------------------------------------------------------------------- #

class AttackObjective(BaseModel):
    """A structured adversarial objective.

    Example objective:
        "Determine whether an actor without premium entitlement can cause
         premium AI inference to execute."

    Represented structurally (not as plain text): target resource, actor,
    the security invariant being challenged, and a success condition.
    """

    id: str = Field(default_factory=new_id)
    campaign_id: str
    actor_id: str
    resource_id: str
    security_invariant_id: str
    success_condition: str = (
        "demonstrate that the actor can perform the forbidden action on the "
        "protected resource without entitlement"
    )
    status: ObjectiveStatus = ObjectiveStatus.FORMULATED


# --------------------------------------------------------------------------- #
# Attack surface / graph
# --------------------------------------------------------------------------- #

class AttackSurface(BaseModel):
    """The reachable surface of a target, discovered before attacking.

    The engine constructs a model of the target: interfaces, resources,
    authentication states, authorization states, and state transitions —
    then builds an attack surface graph.
    """

    id: str = Field(default_factory=new_id)
    target_id: str
    interfaces: list[dict] = Field(default_factory=list)
    resources: list[dict] = Field(default_factory=list)
    auth_states: list[dict] = Field(default_factory=list)
    transitions: list[dict] = Field(default_factory=list)


class AttackPath(BaseModel):
    """One path through the attack graph: actor → interface → resource."""

    id: str = Field(default_factory=new_id)
    actor_id: str
    interface: str
    resource_id: str
    operation: str = "access"
    outcome: TestOutcome = TestOutcome.INCONCLUSIVE


# --------------------------------------------------------------------------- #
# Campaign
# --------------------------------------------------------------------------- #

class Campaign(BaseModel):
    """A complete adversarial assessment; resumable.

    A campaign represents the full adversarial lifecycle against a target:

        Campaign
        ├── Target
        ├── Scope
        ├── Protected Resources
        ├── Actors
        ├── Objectives
        ├── Security Invariants
        ├── Attack Strategies
        ├── Experiments
        ├── Findings
        ├── Evidence
        └── Evolution History
    """

    id: str = Field(default_factory=new_id)
    name: str
    target_id: str
    target_adapter: str = ""
    description: str = ""
    actor_ids: list[str] = Field(default_factory=list)
    resource_ids: list[str] = Field(default_factory=list)
    objective_ids: list[str] = Field(default_factory=list)
    invariant_ids: list[str] = Field(default_factory=list)
    status: CampaignStatus = CampaignStatus.CREATED
    created_at: datetime.datetime = Field(default_factory=utcnow)
    started_at: datetime.datetime | None = None
    completed_at: datetime.datetime | None = None


class CampaignReport(BaseModel):
    """Evidence-based aggregate result of an adversarial campaign."""

    campaign_id: str
    target_id: str
    openmodels_version: str
    status: CampaignStatus = CampaignStatus.COMPLETED
    actors: int = 0
    protected_resources: int = 0
    objectives_formulated: int = 0
    objectives_achieved: int = 0
    invariants_tested: int = 0
    invariants_passed: int = 0
    invariants_violated: int = 0
    paths_tested: int = 0
    findings_created: int = 0
    open_findings: int = 0
    stopped_reason: str = ""


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
