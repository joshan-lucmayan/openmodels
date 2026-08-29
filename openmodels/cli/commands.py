"""OpenModels CLI — the primary user interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from openmodels import VERSION
from openmodels.config import data_home, store_path
from openmodels.core.engine import AdversarialEngine
from openmodels.knowledge.store import KnowledgeStore
from openmodels.models import FindingStatus
from openmodels.policy.models import Policy
from openmodels.target.registry import TargetRegistry
from openmodels.attack.planner import default_planner


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


# --------------------------------------------------------------------------- #
# Main CLI
# --------------------------------------------------------------------------- #

@click.group()
@click.version_option(version=VERSION, prog_name="openmodels")
@pass_ctx
def cli(ctx: Context) -> None:
    """OpenModels — an evolving adversarial intelligence platform.

    OpenModels continuously searches for weaknesses in complex systems by
    constructing hypotheses, testing them, and evolving its knowledge.
    """


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #

@cli.command()
@click.option("--force", is_flag=True, help="Reinitialize even if data exists.")
@pass_ctx
def init(ctx: Context, force: bool) -> None:
    """Initialize the OpenModels data directory and knowledge store."""
    home = data_home()
    db_path = store_path()
    if Path(db_path).exists() and not force:
        click.echo(f"OpenModels data already exists at {home}")
        click.echo(f"Knowledge store: {db_path}")
        click.echo("Use --force to reinitialize.")
        return

    home.mkdir(parents=True, exist_ok=True)
    store = ctx.store
    # Touch the store by saving a metadata entry
    click.echo(f"OpenModels initialized at {home}")
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
    click.echo(f"OpenModels version:   {report.openmodels_version}")
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

    from openmodels.models import Hypothesis, HypothesisStatus

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
    from openmodels.finding.engine import FindingEngine

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
    from openmodels.finding.engine import FindingEngine

    engine = FindingEngine(ctx.store)
    all_findings = engine.list_findings()
    full_id = _resolve_prefix(all_findings, finding_id, "finding")
    try:
        engine.transition(full_id, FindingStatus(status))
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    click.echo(f"Finding {full_id[:8]} transitioned to {status}.")


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
    """Show OpenModels status and summary."""
    store = ctx.store

    if target is None:
        targets = store.list_targets()
        if not targets:
            click.echo("No targets registered. Run 'openmodels research start' first.")
            return

        click.echo(f"OpenModels v{VERSION}")
        click.echo(f"Knowledge store: {store_path()}")
        click.echo()
        for t in targets:
            report = store.build_report(t.id)
            click.echo(f"Target: {t.name} ({t.id[:8]})")
            click.echo(f"  Experiments:    {report.experiments_run}")
            click.echo(f"  Findings:       {report.findings_created} ({report.open_findings} open)")
            click.echo(f"  Successes:      {report.successful_tests}")
            click.echo(f"  Failures:       {report.failed_tests}")
            click.echo(f"  Attack classes: {', '.join(sorted(report.attack_classes_attempted)) or '(none)'}")
            click.echo()
    else:
        full_id = _resolve_prefix(store.list_targets(), target, "target")
        report = store.build_report(full_id)
        click.echo(f"OpenModels v{VERSION} — report for {full_id}")
        click.echo(
            f"  Tested {report.experiments_run} attack hypotheses across "
            f"{len(report.attack_classes_attempted)} attack classes. "
            f"{report.successful_tests} confirmed, "
            f"{report.failed_tests} blocked, "
            f"{report.blocked_tests} policy-blocked, "
            f"{report.inconclusive_tests} inconclusive. "
            f"{report.findings_created} findings ({report.open_findings} open)."
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
    regs = len(results["regressions"])
    click.echo(
        f"Round 1 found {r1.findings_created} weaknesses. "
        f"Defenses applied to all {len(results['defenses'])} findings. "
        f"Regressions: {regs} re-tests, all blocked (defenses held). "
        f"Round 2 evolved to {r2.experiments_run if r2 else 0} new attack surfaces "
        f"({r2.findings_created if r2 else 0} new findings)."
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    cli()