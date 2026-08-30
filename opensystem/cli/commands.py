"""OpenSystem CLI — the primary user interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from opensystem import VERSION
from opensystem.attack.planner import default_planner
from opensystem.config import data_home, store_path
from opensystem.core.engine import AdversarialEngine
from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import FindingStatus, TestOutcome
from opensystem.policy.models import Operation, Policy
from opensystem.target.interface import (
    Capability,
    adapter_capability,
    adapter_supports,
)
from opensystem.target.registry import TargetRegistry

# --------------------------------------------------------------------------- #
# Shared context
# --------------------------------------------------------------------------- #

class Context:
    """Shared CLI context holding store and engine references."""

    def __init__(self) -> None:
        self._store: KnowledgeStore | None = None
        self._registry = TargetRegistry()

    @property
    def store(self) -> KnowledgeStore:
        if self._store is None:
            self._store = KnowledgeStore(store_path())
        return self._store

    def engine(self, policy: Policy | None = None) -> AdversarialEngine:
        return AdversarialEngine(
            store=self.store,
            policy=policy or Policy(),
            planner=default_planner(self.store),
        )

    @property
    def registry(self) -> TargetRegistry:
        return self._registry


pass_ctx = click.make_pass_decorator(Context, ensure=True)


def _resolve_prefix(items: list, prefix: str, label: str) -> str:
    """Resolve an ID prefix to a full ID, raising if ambiguous/unknown."""
    matches = [item.id for item in items if item.id.startswith(prefix)]
    if not matches:
        raise click.ClickException(f"No {label} matches prefix '{prefix}'.")
    if len(matches) > 1:
        raise click.ClickException(
            f"Ambiguous {label} prefix '{prefix}' matches: "
            + ", ".join(m[:8] for m in matches)
        )
    return matches[0]


def _regression_summary(regressions: list) -> str:
    """Summarize regression outcomes from the recorded evidence.

    Every outcome class is reported as recorded — a regression that is not
    blocked is never described as held.
    """
    blocked = sum(1 for r in regressions if r.outcome == TestOutcome.FAILURE)
    exploitable = sum(1 for r in regressions if r.outcome == TestOutcome.SUCCESS)
    other = len(regressions) - blocked - exploitable
    parts = [f"{len(regressions)} re-tests", f"{blocked} blocked"]
    if exploitable:
        parts.append(f"{exploitable} STILL EXPLOITABLE")
    if other:
        parts.append(f"{other} inconclusive")
    return "Regressions: " + ", ".join(parts)


# --------------------------------------------------------------------------- #
# Main CLI
# --------------------------------------------------------------------------- #

@click.group()
@click.version_option(version=VERSION, prog_name="opensystem")
@pass_ctx
def cli(ctx: Context) -> None:
    """OpenSystem — an evolving adversarial intelligence platform.

    OpenSystem continuously searches for weaknesses in complex systems by
    constructing hypotheses, testing them, and evolving its knowledge.
    """


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #

@cli.command()
@click.option("--force", is_flag=True, help="Reinitialize even if data exists.")
@pass_ctx
def init(ctx: Context, force: bool) -> None:
    """Initialize the OpenSystem data directory and knowledge store."""
    home = data_home()
    db_path = store_path()
    if Path(db_path).exists() and not force:
        click.echo(f"OpenSystem data already exists at {home}")
        click.echo(f"Knowledge store: {db_path}")
        click.echo("Use --force to reinitialize.")
        return

    home.mkdir(parents=True, exist_ok=True)
    # Initializing the store creates the schema.
    ctx.store.list_targets()
    click.echo(f"OpenSystem initialized at {home}")
    click.echo(f"Knowledge store: {db_path}")
    click.echo(f"Version: {VERSION}")
    click.echo("Ready.")


# --------------------------------------------------------------------------- #
# target
# --------------------------------------------------------------------------- #

@cli.group()
def target() -> None:
    """Manage target adapters."""


@target.command("list")
@pass_ctx
def target_list(ctx: Context) -> None:
    """List available target adapters."""
    for name in ctx.registry.names():
        click.echo(name)


@target.command("inspect")
@click.argument("name")
@pass_ctx
def target_inspect(ctx: Context, name: str) -> None:
    """Inspect a target adapter's capabilities."""
    try:
        adapter = ctx.registry.create(name)
    except KeyError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    target_model = adapter.discover()
    click.echo(f"Name:        {target_model.name}")
    click.echo(f"Kind:        {target_model.kind}")
    click.echo(f"Adapter:     {target_model.adapter}")
    click.echo(f"Version:     {target_model.version}")
    click.echo(f"Description: {target_model.description}")
    if target_model.assets:
        click.echo(f"Assets:      {', '.join(target_model.assets)}")
    if target_model.interfaces:
        click.echo(f"Interfaces:  {', '.join(target_model.interfaces)}")
    click.echo(f"Created:     {target_model.created_at}")


@target.command("add")
@click.argument("name")
@click.option("--type", "target_type", default="generic", help="Target type.")
@click.option("--adapter", default="mock", help="Target adapter name.")
@click.option("--org", default="", help="Organization.")
@click.option("--env", default="development", help="Environment.")
@click.option("--desc", default="", help="Target description.")
@click.option("--interfaces", default="", help="Comma-separated interface names.")
@click.pass_context
def target_add(
    click_ctx: click.Context,
    name: str,
    target_type: str,
    adapter: str,
    org: str,
    env: str,
    desc: str,
    interfaces: str,
) -> None:
    """Register a target configuration for campaign use.

    The configuration is stored in the data directory and describes what the
    target is, not a specific website. The adapter must be a registered
    adapter type.
    """
    ctx = click_ctx.ensure_object(Context)
    try:
        ctx.registry.get(adapter)
    except KeyError:
        click.echo(f"Error: unknown adapter '{adapter}'.", err=True)
        sys.exit(1)

    from opensystem.models import TargetConfig

    config = TargetConfig(
        name=name,
        target_type=target_type,
        adapter=adapter,
        organization=org,
        environment=env,
        description=desc,
        available_interfaces=(
            [i.strip() for i in interfaces.split(",") if i.strip()]
            if interfaces else []
        ),
    )
    configs = _load_target_configs(ctx)
    configs[name] = config.model_dump(mode="json")
    _save_target_configs(ctx, configs)
    click.echo(f"Target '{name}' registered (adapter={adapter}, type={target_type}).")


def _load_target_configs(ctx: Context) -> dict:
    p = data_home() / "targets.json"
    if p.exists():
        return json.loads(p.read_text())
    return {}


def _save_target_configs(ctx: Context, configs: dict) -> None:
    p = data_home() / "targets.json"
    p.write_text(json.dumps(configs, indent=2, default=str))


# --------------------------------------------------------------------------- #
# research
# --------------------------------------------------------------------------- #

@cli.group()
def research() -> None:
    """Manage research sessions."""


@research.command("start")
@click.argument("target")
@click.option("--rounds", default=10, type=int, help="Number of rounds.")
@click.option("--max-experiments", default=100, type=int, help="Max experiments.")
@click.option("--stop-on-finding", is_flag=True, help="Stop on first finding.")
@pass_ctx
def research_start(
    ctx: Context,
    target: str,
    rounds: int,
    max_experiments: int,
    stop_on_finding: bool,
) -> None:
    """Start a research session against a target adapter."""
    try:
        adapter = ctx.registry.create(target)
    except KeyError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    policy = Policy(
        target_name=target,
        max_rounds=rounds,
        max_experiments=max_experiments,
        stop_on_finding=stop_on_finding,
    )
    engine = ctx.engine(policy)
    report = engine.research(adapter, rounds=rounds)

    click.echo("=== Research Report ===")
    click.echo(f"Target:               {report.target_id}")
    click.echo(f"OpenSystem version:   {report.opensystem_version}")
    click.echo(f"Rounds executed:      {report.rounds_executed}")
    click.echo(f"Hypotheses formed:    {report.hypotheses_formed}")
    click.echo(f"Experiments run:      {report.experiments_run}")
    click.echo(f"Successful:           {report.successful_tests}")
    click.echo(f"Failed:               {report.failed_tests}")
    click.echo(f"Blocked:              {report.blocked_tests}")
    click.echo(f"Inconclusive:         {report.inconclusive_tests}")
    click.echo(f"Findings created:     {report.findings_created}")
    click.echo(f"Open findings:        {report.open_findings}")
    click.echo(f"Attack classes:       {', '.join(sorted(report.attack_classes_attempted)) or '(none)'}")
    click.echo(f"Stopped reason:       {report.stopped_reason}")


# --------------------------------------------------------------------------- #
# experiment
# --------------------------------------------------------------------------- #

@cli.group()
def experiment() -> None:
    """Manage experiments."""


@experiment.command("run")
@click.argument("target")
@click.argument("hypothesis_statement")
@click.option(
    "--weakness",
    default=None,
    help="Mock-target weakness key to test (e.g. auth-bypass).",
)
@pass_ctx
def experiment_run(
    ctx: Context, target: str, hypothesis_statement: str, weakness: str | None
) -> None:
    """Run a single experiment against a target."""
    try:
        adapter = ctx.registry.create(target)
    except KeyError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    from opensystem.models import Hypothesis, HypothesisStatus

    hypothesis = Hypothesis(
        target_id="",
        statement=hypothesis_statement,
        status=HypothesisStatus.PROPOSED,
        origin=f"strategy:{weakness}" if weakness else "manual",
    )

    engine = ctx.engine()
    experiment = engine.run_experiment(adapter, hypothesis)

    click.echo("=== Experiment ===")
    click.echo(f"ID:         {experiment.id}")
    click.echo(f"Hypothesis: {experiment.hypothesis_id}")
    click.echo(f"Test:       {experiment.test.name}")
    click.echo(f"Outcome:    {experiment.outcome.value}")
    click.echo(f"Result:     {experiment.observed_result}")
    click.echo(f"Conclusion: {experiment.conclusion}")


# --------------------------------------------------------------------------- #
# finding
# --------------------------------------------------------------------------- #

@cli.group()
def finding() -> None:
    """Manage findings."""


@finding.command("list")
@click.option("--target", default=None, help="Filter by target ID.")
@click.option("--open", "only_open", is_flag=True, help="Show only open findings.")
@pass_ctx
def finding_list(ctx: Context, target: str | None, only_open: bool) -> None:
    """List findings."""
    from opensystem.finding.engine import FindingEngine

    engine = FindingEngine(ctx.store)
    findings = engine.list_findings(target)
    if only_open:
        findings = [f for f in findings if f.verification_status != FindingStatus.CLOSED]

    if not findings:
        click.echo("No findings.")
        return

    for f in findings:
        status = f.verification_status.value
        click.echo(
            f"[{status}] {f.id[:8]} | {f.severity.value:8s} | "
            f"{f.affected_component} | {f.attack_hypothesis[:60]}"
        )


@finding.command("transition")
@click.argument("finding_id")
@click.argument("status", type=click.Choice([s.value for s in FindingStatus]))
@pass_ctx
def finding_transition(ctx: Context, finding_id: str, status: str) -> None:
    """Transition a finding to a new status."""
    from opensystem.finding.engine import FindingEngine

    engine = FindingEngine(ctx.store)
    all_findings = engine.list_findings()
    full_id = _resolve_prefix(all_findings, finding_id, "finding")
    try:
        engine.transition(full_id, FindingStatus(status))
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    click.echo(f"Finding {full_id[:8]} transitioned to {status}.")


@finding.command("prove")
@click.argument("finding_id")
@click.option("--expires-hours", default=24, type=int,
              help="Proof-key validity window in hours (default 24).")
@click.option("--adapter", default=None,
              help="Target adapter name (default: derived from finding).")
@pass_ctx
def finding_prove(
    ctx: Context, finding_id: str, expires_hours: int, adapter: str | None
) -> None:
    """Generate a show-once proof key for a CONFIRMED finding.

    The raw key is displayed EXACTLY ONCE. OpenSystem stores only a SHA-256
    hash. The key authenticates ONLY against the authorized test target for
    the affected actor; it grants no additional privileges.
    """
    from opensystem.finding.engine import FindingEngine
    from opensystem.proof.service import ProofKeyError, ProofSessionService

    if expires_hours < 0:
        click.echo("Error: --expires-hours must not be negative.", err=True)
        sys.exit(1)

    all_findings = FindingEngine(ctx.store).list_findings()
    full_id = _resolve_prefix(all_findings, finding_id, "finding")
    finding = next(f for f in all_findings if f.id == full_id)

    if finding.verification_status != FindingStatus.CONFIRMED:
        click.echo(
            f"Error: finding {full_id[:8]} is {finding.verification_status.value}, "
            "not CONFIRMED. Run 'opensystem impact verify <finding-id>' first.",
            err=True)
        sys.exit(1)

    # Impact must already be independently verified.
    verifications = ctx.store.get_impact_verifications(full_id)
    if not verifications or not verifications[0].verified:
        click.echo(
            "Error: no passing impact verification. Run "
            "'opensystem impact verify <finding-id>' first.", err=True)
        sys.exit(1)

    # Identify the target adapter.
    target = ctx.store.get_target(finding.target_id)
    if target is None:
        click.echo("Error: target for finding not found.", err=True)
        sys.exit(1)
    adapter_name = adapter or target.adapter
    try:
        target_adapter = ctx.registry.create(adapter_name)
    except KeyError:
        click.echo(f"Error: unknown adapter '{adapter_name}'.", err=True)
        sys.exit(1)

    if not adapter_supports(target_adapter, Capability.PROOF_SESSION):
        click.echo(
            f"Error: target adapter '{adapter_name}' does not support proof "
            "sessions.", err=True)
        sys.exit(1)

    # Operator explicitly requests a proof session: policy permits it and is
    # scoped to this target.
    policy = Policy(
        target_name=adapter_name,
        allowed_operations=[
            Operation.OBSERVE, Operation.TEST, Operation.RESET,
            Operation.PROOF_SESSION,
        ],
    )
    service = ProofSessionService(ctx.store, policy=policy)
    campaign_id = ""
    for c in ctx.store.list_campaigns():
        if c.target_id == finding.target_id:
            campaign_id = c.id
            break

    try:
        result = service.create(
            finding, target_adapter, target,
            campaign_id=campaign_id, expires_hours=expires_hours,
        )
    except ProofKeyError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    session = result.session
    actor = ctx.store.get_actor(session.actor_id)
    resource = ctx.store.get_protected_resource(session.resource_id)

    click.echo("")
    click.echo("=" * 50)
    click.echo("OPENSYSTEM — PROOF SESSION")
    click.echo("=" * 50)
    click.echo("Finding:")
    click.echo(f"  {full_id}")
    click.echo("")
    click.echo("Status:")
    click.echo("  CONFIRMED")
    click.echo("")
    click.echo("Target:")
    click.echo(f"  {target.name} (adapter={adapter_name})")
    click.echo("")
    click.echo("Actor:")
    click.echo(f"  {actor.name.upper() if actor else session.actor_id}")
    click.echo("")
    click.echo("Protected Resource:")
    click.echo(f"  {resource.name.upper() if resource else session.resource_id}")
    click.echo("")
    click.echo("Impact:")
    click.echo(f"  {finding.impact}")
    click.echo("")
    click.echo("=" * 50)
    click.echo("PROOF KEY")
    click.echo("=" * 50)
    click.echo("Username:")
    click.echo(f"  {session.username}")
    click.echo("")
    click.echo("Key:")
    click.echo(f"  {result.raw_key}")
    click.echo("")
    click.echo("IMPORTANT:")
    click.echo("  Copy this key now. The raw key will NOT be displayed again.")
    click.echo("  OpenSystem stores only a secure hash.")
    click.echo("")
    click.echo(f"Expires: {session.expires_at.isoformat()}")
    click.echo("")
    click.echo("=" * 50)
    click.echo("PROOF SESSION")
    click.echo("=" * 50)
    click.echo(f"Session ID: {session.id}")
    click.echo("")
    click.echo("Status:")
    click.echo("  ACTIVE")
    click.echo("")
    click.echo("The proof key is bound to:")
    click.echo(f"  Finding: {full_id}")
    click.echo(f"  Target:  {target.name}")
    click.echo(f"  Actor:   {actor.name.upper() if actor else '?'}")
    click.echo("")
    click.echo("The key authenticates ONLY against the authorized test target.")
    click.echo("=" * 50)
    click.echo("")


# --------------------------------------------------------------------------- #
# impact
# --------------------------------------------------------------------------- #

@cli.group()
def impact() -> None:
    """Impact verification for findings."""


@impact.command("verify")
@click.argument("finding_id")
@pass_ctx
def impact_verify(ctx: Context, finding_id: str) -> None:
    """Independently verify that a finding reached the protected resource."""
    from opensystem.finding.engine import FindingEngine
    from opensystem.impact.engine import ImpactNotVerified, ImpactVerifier

    all_findings = FindingEngine(ctx.store).list_findings()
    full_id = _resolve_prefix(all_findings, finding_id, "finding")
    finding = next(f for f in all_findings if f.id == full_id)

    target = ctx.store.get_target(finding.target_id)
    if target is None:
        click.echo("Error: target for finding not found.", err=True)
        sys.exit(1)
    try:
        target_adapter = ctx.registry.create(target.adapter)
    except KeyError:
        click.echo(f"Error: unknown adapter '{target.adapter}'.", err=True)
        sys.exit(1)

    verifier = ImpactVerifier(ctx.store)
    try:
        verification = verifier.verify(finding, target_adapter, target)
    except ImpactNotVerified as exc:
        # The failed verification record is persisted for the audit trail.
        click.echo(f"Impact NOT verified: {exc}", err=True)
        sys.exit(1)

    # Mark the finding CONFIRMED once impact is verified.
    ctx.store.update_finding_status(full_id, FindingStatus.CONFIRMED)

    click.echo("=== Impact Verification ===")
    click.echo(f"Finding:   {full_id[:8]}")
    click.echo(f"Verified:  {verification.verified}")
    click.echo(f"Method:    {verification.method}")
    if verification.verified:
        detail = verification.detail
        click.echo(f"Resource:  {detail.get('resource')}")
        click.echo(f"Interface: {detail.get('interface')}")
        click.echo(f"Payload:   {detail.get('payload')}")
        click.echo("Status:    CONFIRMED — ready for proof session.")
    else:
        click.echo("Status:    NOT verified.")


# --------------------------------------------------------------------------- #
# proof-key
# --------------------------------------------------------------------------- #

@cli.group()
def proof_key() -> None:
    """Manage show-once proof keys (masked reads only)."""


@proof_key.command("inspect")
@click.argument("session_id")
@pass_ctx
def proof_key_inspect(ctx: Context, session_id: str) -> None:
    """Inspect a proof session (masked key — raw key is never returned)."""
    from opensystem.proof.service import ProofSessionService

    service = ProofSessionService(ctx.store)
    session = service.inspect(_resolve_prefix(
        ctx.store.list_proof_sessions(), session_id, "proof session"
    ))
    if session is None:
        click.echo("Proof session not found.", err=True)
        sys.exit(1)
    _render_proof_session(ctx, session)


def _render_proof_session(ctx: Context, session) -> None:
    from opensystem.proof.service import mask_key

    actor = ctx.store.get_actor(session.actor_id)
    resource = ctx.store.get_protected_resource(session.resource_id)

    click.echo("Proof Session:")
    click.echo(f"  {session.id}")
    click.echo("")
    click.echo("Finding:")
    click.echo(f"  {session.finding_id}")
    click.echo("")
    click.echo("Actor:")
    click.echo(f"  {actor.name.upper() if actor else session.actor_id}")
    click.echo("")
    click.echo("Target:")
    click.echo(f"  {session.target_adapter}")
    click.echo("")
    click.echo("Protected Resource:")
    click.echo(f"  {resource.name.upper() if resource else session.resource_id}")
    click.echo("")
    click.echo("Key:")
    click.echo(f"  {session.username}")
    click.echo(f"  {mask_key(session)}")  # masked — secret never stored
    click.echo("")
    click.echo("Status:")
    click.echo(f"  {session.status.value}")
    click.echo("")
    click.echo("Created:")
    click.echo(f"  {session.created_at.isoformat()}")
    click.echo("")
    if session.revoked_at:
        click.echo("Revoked:")
        click.echo(f"  {session.revoked_at.isoformat()}")
        click.echo("")
    click.echo("Expires:")
    click.echo(f"  {session.expires_at.isoformat()}")
    click.echo("")
    click.echo("Last Used:")
    click.echo(f"  {session.last_used_at.isoformat() if session.last_used_at else 'never'}")
    click.echo("")
    click.echo("The raw key is NOT stored and can NOT be retrieved.")


@proof_key.command("list")
@pass_ctx
def proof_key_list(ctx: Context) -> None:
    """List proof sessions (metadata only, never raw keys)."""
    from opensystem.proof.service import ProofSessionService

    sessions = ProofSessionService(ctx.store).list()
    if not sessions:
        click.echo("No proof sessions.")
        return
    click.echo(
        f"{'ID':<16} {'FINDING':<16} {'ACTOR':<12} {'STATUS':<8} EXPIRES"
    )
    for s in sessions:
        actor = ctx.store.get_actor(s.actor_id)
        name = actor.name.upper() if actor else s.actor_id[:6]
        click.echo(
            f"{s.id:<16} {s.finding_id:<16} {name:<12} "
            f"{s.status.value:<8} {s.expires_at.strftime('%Y-%m-%d %H:%M')}"
        )


@proof_key.command("revoke")
@click.argument("session_id")
@pass_ctx
def proof_key_revoke(ctx: Context, session_id: str) -> None:
    """Immediately revoke a proof session."""
    from opensystem.proof.service import ProofSessionService

    service = ProofSessionService(ctx.store)
    full_id = _resolve_prefix(ctx.store.list_proof_sessions(), session_id, "proof session")
    session = service.revoke(full_id)
    if session is None:
        click.echo("Proof session not found.", err=True)
        sys.exit(1)
    click.echo(f"Proof session {full_id} revoked.")
    click.echo("The associated credential now fails validation.")


@proof_key.command("verify")
@click.option("--stdin", "use_stdin", is_flag=True,
              help="Read the key from stdin (avoids shell-history exposure).")
@pass_ctx
def proof_key_verify(ctx: Context, use_stdin: bool) -> None:
    """Validate a presented proof key against the authorized test interface.

    SECRET-HANDLING DESIGN (documented per the proof-session spec):

    This command deliberately does NOT accept the raw key as a positional
    argument or a --key flag. A key passed as an argument is recorded in the
    shell history (and often in process listings), creating a leakage
    channel. Instead the key is read from:

      * stdin (--stdin), e.g. ``echo "$KEY" | opensystem proof-key verify --stdin``
      * an interactive no-echo prompt (getpass) when run without --stdin

    The key is never echoed, never logged, never included in exceptions,
    and never included in command output.
    """
    from opensystem.proof.service import ProofSessionService

    if use_stdin:
        raw_key = sys.stdin.readline().strip()
    else:
        import getpass

        raw_key = getpass.getpass("Proof key: ").strip()

    if not raw_key:
        click.echo("No key provided.", err=True)
        sys.exit(1)

    result = ProofSessionService(ctx.store).verify(raw_key)
    if result.ok and result.session:
        actor = ctx.store.get_actor(result.session.actor_id)
        resource = ctx.store.get_protected_resource(result.session.resource_id)
        click.echo("=== Authentication Successful ===")
        click.echo(f"Session:    {result.session.id}")
        click.echo(f"Finding:    {result.session.finding_id}")
        click.echo(f"Actor:      {actor.name.upper() if actor else '?'}")
        click.echo(f"Resource:   {resource.name.upper() if resource else '?'}")
        click.echo(f"Status:     {result.session.status.value}")
    else:
        # Failure reasons are generic identifiers; the presented key is
        # never echoed back.
        click.echo(f"Authentication failed: {result.reason}", err=True)
        sys.exit(1)


# --------------------------------------------------------------------------- #
# case-study
# --------------------------------------------------------------------------- #

@cli.group()
def case_study() -> None:
    """Reproducible written case studies for confirmed findings."""


@case_study.command("create")
@click.argument("finding_id")
@pass_ctx
def case_study_create(ctx: Context, finding_id: str) -> None:
    """Create a case study for a finding (never contains the raw key)."""
    from opensystem.finding.engine import FindingEngine
    from opensystem.proof.service import build_case_study

    all_findings = FindingEngine(ctx.store).list_findings()
    full_id = _resolve_prefix(all_findings, finding_id, "finding")
    finding = next(f for f in all_findings if f.id == full_id)

    # Case studies document confirmed findings only; the verification status
    # recorded in the report is always the store's own record.
    if finding.verification_status != FindingStatus.CONFIRMED:
        click.echo(
            f"Error: finding {full_id[:8]} is {finding.verification_status.value}, "
            "not CONFIRMED. Run 'opensystem impact verify <finding-id>' first.",
            err=True)
        sys.exit(1)

    target = ctx.store.get_target(finding.target_id)
    if target is None:
        click.echo("Error: target not found.", err=True)
        sys.exit(1)
    adapter = ctx.registry.create(target.adapter)

    campaign_id = ""
    for c in ctx.store.list_campaigns():
        if c.target_id == target.id:
            campaign_id = c.id
            break

    cs = build_case_study(ctx.store, finding, adapter, target, campaign_id)
    click.echo(f"Case study created: {cs.id[:8]}")
    click.echo(f"Finding: {full_id[:8]}")
    click.echo("Run 'opensystem case-study show <id>' to view.")


@case_study.command("list")
@pass_ctx
def case_study_list(ctx: Context) -> None:
    """List case studies."""
    studies = ctx.store.list_case_studies()
    if not studies:
        click.echo("No case studies.")
        return
    for cs in studies:
        click.echo(f"{cs.id[:8]} | {cs.title} | finding={cs.finding_id[:8]}")


@case_study.command("show")
@click.argument("case_study_id")
@pass_ctx
def case_study_show(ctx: Context, case_study_id: str) -> None:
    """Display a case study."""
    studies = ctx.store.list_case_studies()
    full_id = _resolve_prefix(studies, case_study_id, "case study")
    cs = ctx.store.get_case_study(full_id)
    if cs is None:
        click.echo("Case study not found.", err=True)
        sys.exit(1)
    click.echo(f"# {cs.title}")
    click.echo(f"Case study: {cs.id}")
    for key, value in cs.body.items():
        if isinstance(value, dict):
            click.echo(f"{key}:")
            for k, v in value.items():
                click.echo(f"  {k}: {v}")
        else:
            click.echo(f"{key}: {value}")
    click.echo("")
    click.echo("This report contains NO raw proof keys.")


@case_study.command("export")
@click.argument("case_study_id")
@click.option("--output", "-o", default=None, help="Output file path.")
@pass_ctx
def case_study_export(ctx: Context, case_study_id: str, output: str | None) -> None:
    """Export a case study to a JSON file (raw proof key never included)."""
    import json as _json

    studies = ctx.store.list_case_studies()
    full_id = _resolve_prefix(studies, case_study_id, "case study")
    cs = ctx.store.get_case_study(full_id)
    if cs is None:
        click.echo("Case study not found.", err=True)
        sys.exit(1)

    payload = {
        "case_study_id": cs.id,
        "title": cs.title,
        "finding_id": cs.finding_id,
        "created_at": cs.created_at.isoformat(),
        "body": cs.body,
    }

    if output is None:
        output = str(data_home() / "case-studies" / f"{cs.id}.json")
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_json.dumps(payload, indent=2, default=str))
    click.echo(f"Exported case study to {out_path}")
    click.echo("Note: the raw proof key is never included in exports.")


# --------------------------------------------------------------------------- #
# attack
# --------------------------------------------------------------------------- #

@cli.group()
def attack() -> None:
    """Manage attack strategies."""


@attack.command("list")
@pass_ctx
def attack_list(ctx: Context) -> None:
    """List available attack strategies."""
    planner = default_planner(ctx.store)
    for s in planner.list_strategies():
        click.echo(f"[{s.family:20s}] {s.name:25s} {s.description}")


# --------------------------------------------------------------------------- #
# campaign
# --------------------------------------------------------------------------- #

@cli.group()
def campaign() -> None:
    """Manage adversarial campaigns."""


@campaign.command("create")
@click.argument("target")
@click.argument("name")
@click.option("--desc", default="", help="Campaign description.")
@click.option("--max-experiments", default=100, type=int,
              help="Max experiments in the campaign.")
@pass_ctx
def campaign_create(
    ctx: Context, target: str, name: str, desc: str, max_experiments: int
) -> None:
    """Create a campaign against a target adapter."""
    try:
        adapter = ctx.registry.create(target)
    except KeyError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    from opensystem.campaign.engine import CampaignEngine
    from opensystem.policy.models import Policy

    engine = CampaignEngine(ctx.store, policy=Policy(
        target_name=target, max_experiments=max_experiments,
    ))

    target_model = adapter.discover()

    # Build actors and resources from the adapter's security model.
    actors_fn = adapter_capability(adapter, Capability.SECURITY_MODEL, "actors")
    resources_fn = adapter_capability(adapter, Capability.SECURITY_MODEL, "resources")
    actors = list(actors_fn().values()) if actors_fn else []
    resources = list(resources_fn().values()) if resources_fn else []

    campaign = engine.create_campaign(
        name=name,
        target_adapter=adapter,
        target=target_model,
        description=desc,
        actors=actors,
        resources=resources,
    )
    engine.discover(campaign, adapter, target_model)

    objectives = ctx.store.list_objectives(campaign.id)
    click.echo(f"Campaign created: {campaign.id[:8]} ({name})")
    click.echo(f"  Target:     {target_model.name}")
    click.echo(f"  Actors:     {', '.join(campaign.actor_ids) or '(none)'}")
    click.echo(f"  Resources:  {', '.join(campaign.resource_ids) or '(none)'}")
    click.echo(f"  Objectives: {len(objectives)} formulated")
    click.echo("Run it with: opensystem campaign run <campaign_id>")


@campaign.command("run")
@click.argument("campaign_id")
@pass_ctx
def campaign_run(ctx: Context, campaign_id: str) -> None:
    """Run a campaign to completion."""
    from opensystem.campaign.engine import CampaignEngine

    engine = CampaignEngine(ctx.store)
    campaigns = ctx.store.list_campaigns()
    full_id = _resolve_prefix(campaigns, campaign_id, "campaign")
    campaign = engine.resume(full_id)
    if campaign is None:
        click.echo("Campaign not found.", err=True)
        sys.exit(1)

    adapter = ctx.registry.create(campaign.target_adapter)
    target_model = adapter.discover()
    if target_model.id != campaign.target_id:
        target_model = ctx.store.get_target(campaign.target_id) or target_model

    report = engine.run(campaign, adapter, target_model)

    click.echo("=== Campaign Report ===")
    click.echo(f"Campaign:         {report.campaign_id[:8]}")
    click.echo(f"Status:           {report.status.value}")
    click.echo(f"Actors:           {report.actors}")
    click.echo(f"Protected res.:   {report.protected_resources}")
    click.echo(f"Objectives:       {report.objectives_formulated}")
    click.echo(f"  achieved:       {report.objectives_achieved}")
    click.echo(f"Invariants tested:{report.invariants_tested}")
    click.echo(f"  passed (held):  {report.invariants_passed}")
    click.echo(f"  violated:       {report.invariants_violated}")
    click.echo(f"Paths tested:     {report.paths_tested}")
    click.echo(f"Findings:         {report.findings_created} ({report.open_findings} open)")
    click.echo("Findings: opensystem finding list")


@campaign.command("enforce")
@click.argument("campaign_id")
@pass_ctx
def campaign_enforce(ctx: Context, campaign_id: str) -> None:
    """Run the adversarial improvement cycle for a campaign.

    Runs the campaign, then simulates the defender enforcing each violated
    security boundary, then re-runs the campaign to show the boundaries now
    hold (regression).
    """
    from opensystem.campaign.engine import CampaignEngine

    engine = CampaignEngine(ctx.store)
    campaigns = ctx.store.list_campaigns()
    full_id = _resolve_prefix(campaigns, campaign_id, "campaign")
    campaign = engine.resume(full_id)
    if campaign is None:
        click.echo("Campaign not found.", err=True)
        sys.exit(1)

    adapter = ctx.registry.create(campaign.target_adapter)
    target_model = ctx.store.get_target(campaign.target_id) or adapter.discover()

    results = engine.enforce_and_revalidate(campaign, adapter, target_model)

    click.echo("=== Adversarial Improvement Cycle ===")
    r1 = results["first_round"]
    r2 = results["second_round"]
    click.echo(f"Round 1: {r1.invariants_violated} boundary violations, "
               f"{r1.findings_created} findings.")
    click.echo(f"Defender enforced {len(results['enforced'])} boundaries:")
    for e in results["enforced"]:
        click.echo(f"  - {e['interface']} → {e['resource']}")
    click.echo(f"Round 2 (revalidated): {r2.invariants_violated} violations, "
               f"{r2.invariants_passed} held, {r2.findings_created} new findings.")
    click.echo(
        "Security boundary evolution complete: previously-violated "
        "boundaries now hold."
    )


@campaign.command("graph")
@click.argument("campaign_id")
@pass_ctx
def campaign_graph(ctx: Context, campaign_id: str) -> None:
    """Render the attack graph for a campaign."""
    from opensystem.campaign.graph import AttackGraph

    campaigns = ctx.store.list_campaigns()
    full_id = _resolve_prefix(campaigns, campaign_id, "campaign")
    campaign = ctx.store.get_campaign(full_id)
    if campaign is None:
        click.echo("Campaign not found.", err=True)
        sys.exit(1)

    adapter = ctx.registry.create(campaign.target_adapter)
    actors = [
        ctx.store.get_actor(a) for a in campaign.actor_ids
        if ctx.store.get_actor(a) is not None
    ]
    resources = [
        ctx.store.get_protected_resource(r) for r in campaign.resource_ids
        if ctx.store.get_protected_resource(r) is not None
    ]
    tested = ctx.store.list_attack_paths(actor_ids=campaign.actor_ids)

    graph = AttackGraph(ctx.store).build(
        campaign.target_id, actors, resources, adapter, tested
    )
    click.echo(f"Attack graph for {campaign.name} ({full_id[:8]})")
    for p in graph["paths"]:
        click.echo(
            f"  {p['actor']:12s} → {p['interface']:12s} → "
            f"{p['resource']:16s} [decision={p['decision']}, "
            f"outcome={p['outcome']}]"
        )


@campaign.command("list")
@pass_ctx
def campaign_list(ctx: Context) -> None:
    """List campaigns."""
    campaigns = ctx.store.list_campaigns()
    if not campaigns:
        click.echo("No campaigns yet.")
        return
    for c in campaigns:
        click.echo(
            f"[{c.status.value}] {c.id[:8]} | {c.name} | target={c.target_adapter}"
        )


@campaign.command("show")
@click.argument("campaign_id")
@pass_ctx
def campaign_show(ctx: Context, campaign_id: str) -> None:
    """Show campaign details, including objectives and invariants."""
    campaigns = ctx.store.list_campaigns()
    full_id = _resolve_prefix(campaigns, campaign_id, "campaign")
    campaign = ctx.store.get_campaign(full_id)
    if campaign is None:
        click.echo("Campaign not found.", err=True)
        sys.exit(1)

    click.echo(f"Campaign: {campaign.id} ({campaign.name})")
    click.echo(f"  Status:   {campaign.status.value}")
    click.echo(f"  Target:   {campaign.target_id}")
    click.echo(f"  Adapter:  {campaign.target_adapter}")
    click.echo(f"  Created:  {campaign.created_at}")

    objectives = ctx.store.list_objectives(campaign.id)
    click.echo(f"  Objectives ({len(objectives)}):")
    for o in objectives:
        actor = ctx.store.get_actor(o.actor_id)
        resource = ctx.store.get_protected_resource(o.resource_id)
        a = actor.name if actor else o.actor_id
        r = resource.name if resource else o.resource_id
        click.echo(
            f"    [{o.status.value}] {a} → {r} "
            f"(invariant {o.security_invariant_id[:8]})"
        )

    surface = ctx.store.get_attack_surface(campaign.target_id)
    if surface:
        click.echo(f"  Attack surface ({len(surface.interfaces)} interfaces):")
        for i in surface.interfaces:
            click.echo(f"    - {i.get('name')}")


# --------------------------------------------------------------------------- #
# knowledge
# --------------------------------------------------------------------------- #

@cli.group()
def knowledge() -> None:
    """Manage the knowledge store."""


@knowledge.command("search")
@click.argument("query")
@click.option("--target", default=None, help="Filter by target ID.")
@pass_ctx
def knowledge_search(ctx: Context, query: str, target: str | None) -> None:
    """Search the knowledge store."""
    results = ctx.store.search_knowledge(query, target)
    if not results:
        click.echo("No results.")
        return
    for k in results:
        click.echo(f"[{k.kind.value:20s}] {k.content[:80]}")
        click.echo(f"        provenance: {k.provenance}, created: {k.created_at}")
        click.echo()


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #

@cli.command()
@click.option("--target", default=None, help="Target ID for scoped report.")
@pass_ctx
def status(ctx: Context, target: str | None) -> None:
    """Show OpenSystem status and summary."""
    store = ctx.store

    if target is None:
        targets = store.list_targets()
        if not targets:
            click.echo("No targets registered. Run 'opensystem research start' first.")
            return

        click.echo(f"OpenSystem v{VERSION}")
        click.echo(f"Knowledge store: {store_path()}")
        click.echo()
        for t in targets:
            report = store.build_report(t.id)
            click.echo(f"Target: {t.name} ({t.id[:8]})")
            click.echo(f"  Experiments:    {report.experiments_run}")
            if report.campaign_paths_tested:
                click.echo(
                    f"  Boundary tests: {report.campaign_paths_tested} "
                    f"({report.campaign_violations} boundary crossings)"
                )
            click.echo(f"  Findings:       {report.findings_created} ({report.open_findings} open)")
            click.echo(f"  Successes:      {report.successful_tests}")
            click.echo(f"  Failures:       {report.failed_tests}")
            click.echo(f"  Attack classes: {', '.join(sorted(report.attack_classes_attempted)) or '(none)'}")
            click.echo()
    else:
        full_id = _resolve_prefix(store.list_targets(), target, "target")
        report = store.build_report(full_id)
        click.echo(f"OpenSystem v{VERSION} — report for {full_id}")
        click.echo(
            f"  Tested {report.experiments_run} attack hypotheses across "
            f"{len(report.attack_classes_attempted)} attack classes. "
            f"{report.successful_tests} confirmed, "
            f"{report.failed_tests} blocked, "
            f"{report.blocked_tests} policy-blocked, "
            f"{report.inconclusive_tests} inconclusive. "
            f"{report.findings_created} findings ({report.open_findings} open)."
        )
        if report.campaign_paths_tested:
            click.echo(
                f"  Campaign boundary tests: {report.campaign_paths_tested} "
                f"({report.campaign_violations} crossings)."
            )


# --------------------------------------------------------------------------- #
# security-test
# --------------------------------------------------------------------------- #

@cli.command()
@click.argument("target")
@click.option("--rounds", default=5, type=int, help="Rounds per session.")
@pass_ctx
def security_test(ctx: Context, target: str, rounds: int) -> None:
    """Run the full adversarial cycle: attack → defend → evolve → attack.

    This demonstrates the evolution loop: findings discovered, defenses
    applied, regressions verified, and new hypotheses generated.
    """
    try:
        adapter = ctx.registry.create(target)
    except KeyError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    engine = ctx.engine()
    results = engine.security_test(adapter, rounds=rounds)

    click.echo("=== First Round: Attack ===")
    r1 = results["first_round"]
    click.echo(f"  Experiments: {r1.experiments_run}, Findings: {r1.findings_created}")

    click.echo("=== Defenses Applied ===")
    for d in results["defenses"]:
        click.echo(f"  {d.id[:8]} | {d.description}")

    click.echo("=== Regressions ===")
    for r in results["regressions"]:
        click.echo(
            f"  {r.id[:8]} | hypothesis {r.hypothesis_id[:8]} "
            f"| outcome {r.outcome.value}"
        )

    click.echo("=== Second Round: Evolved Attack ===")
    r2 = results["second_round"]
    if r2:
        click.echo(f"  Experiments: {r2.experiments_run}, Findings: {r2.findings_created}")
        click.echo(f"  New hypotheses: {r2.hypotheses_formed}")
        click.echo(f"  Attack classes: {', '.join(sorted(r2.attack_classes_attempted))}")

    click.echo("=== Evolution Summary ===")
    click.echo(
        f"Round 1 found {r1.findings_created} weaknesses. "
        f"Defenses applied to {len(results['defenses'])} findings. "
        f"{_regression_summary(results['regressions'])}."
    )
    click.echo(
        f"Round 2 evolved to {r2.experiments_run if r2 else 0} new attack surfaces "
        f"({r2.findings_created if r2 else 0} new findings)."
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    cli()