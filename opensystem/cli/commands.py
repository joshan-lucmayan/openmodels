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
from opensystem.models import FindingStatus
from opensystem.policy.models import Policy
from opensystem.target.registry import TargetRegistry

# --------------------------------------------------------------------------- #
# Shared context
# --------------------------------------------------------------------------- #

class Context:
    """Shared CLI context holding store and engine references."""

    def __init__(self) -> None:
        self._store: KnowledgeStore | None = None
        self._registry = TargetRegistry()
        self._target_configs: dict | None = None

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

    # ------------------------------------------------------------------ #
    # Target configuration resolution
    # ------------------------------------------------------------------ #

    def load_target_configs(self) -> dict:
        if self._target_configs is None:
            p = data_home() / "targets.json"
            self._target_configs = (
                json.loads(p.read_text()) if p.exists() else {}
            )
        return self._target_configs

    def save_target_configs(self, configs: dict) -> None:
        self._target_configs = configs
        p = data_home() / "targets.json"
        p.write_text(json.dumps(configs, indent=2, default=str))

    def adapter_for(self, name: str, **overrides):
        """Resolve a CLI target reference to an adapter instance.

        ``name`` may be either a registered adapter type (e.g. "http") or a
        saved target configuration name (registered via ``target add``).
        Saved configs carry the connection parameters (e.g. base URL) for
        live targets.
        """
        configs = self.load_target_configs()
        if name in configs:
            config = dict(configs[name])
            config.update(overrides)
            adapter_type = config.get("adapter", "http")
            cls = self.registry.get(adapter_type)
            if hasattr(cls, "from_config"):
                return cls.from_config(config)
            return cls(**{k: v for k, v in config.items()
                          if k in _allowed_init_params(cls)})
        return self.registry.create(name, **overrides)


def _allowed_init_params(cls) -> set[str]:
    """Introspect an adapter class's __init__ parameter names."""
    import inspect

    try:
        return set(inspect.signature(cls.__init__).parameters)
    except (TypeError, ValueError):
        return set()


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
@click.version_option(version=VERSION, prog_name="opensystem")
@pass_ctx
def cli(ctx: Context) -> None:
    """OpenSystem — an evolving adversarial intelligence platform.

    OpenSystem continuously searches for weaknesses in complex systems by
    constructing hypotheses, testing them, and evolving its knowledge.
    """


def _echo_report(report) -> None:
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
    """Inspect a target adapter or saved target configuration."""
    try:
        adapter = ctx.adapter_for(name)
    except (KeyError, ValueError) as e:
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
@click.option("--adapter", default="http", help="Target adapter name.")
@click.option("--url", default=None, help="Base URL (http adapter).")
@click.option("--org", default="", help="Organization.")
@click.option("--env", default=None, help="Environment.")
@click.option("--desc", default="", help="Target description.")
@click.option("--interfaces", default="", help="Comma-separated interface names.")
@click.option(
    "--scope", default="",
    help="Authorized testing scope (e.g. 'https://host/*').",
)
@click.option(
    "--allow-insecure-tls", is_flag=True,
    help="Disable TLS verification for test environments with self-signed certs.",
)
@click.option(
    "--confirm-authorized", is_flag=True,
    required=False, default=False,
    help="Explicitly confirm you are authorized to test this target.",
)
@click.pass_context
def target_add(
    click_ctx: click.Context,
    name: str,
    target_type: str,
    adapter: str,
    url: str | None,
    org: str,
    env: str | None,
    desc: str,
    interfaces: str,
    scope: str,
    allow_insecure_tls: bool,
    confirm_authorized: bool,
) -> None:
    """Register a target configuration for campaign use.

    The configuration describes the target and the operator's authorization.
    Live targets (adapter=http) require --url and --confirm-authorized.
    """
    ctx = click_ctx.ensure_object(Context)
    try:
        ctx.registry.get(adapter)
    except KeyError:
        click.echo(f"Error: unknown adapter '{adapter}'.", err=True)
        sys.exit(1)

    if env is None:
        env = "production" if adapter == "http" else "development"

    if adapter == "http":
        if not url:
            click.echo("Error: --url is required for adapter 'http'.", err=True)
            sys.exit(1)
        if not confirm_authorized:
            click.echo(
                "Error: live targets require --confirm-authorized. "
                "Only register targets you have permission to test.",
                err=True,
            )
            sys.exit(1)
        if scope == "":
            scope = f"{url.rstrip('/')}/*"

    from opensystem.models import TargetConfig

    config = TargetConfig(
        name=name,
        target_type=target_type,
        adapter=adapter,
        organization=org,
        environment=env,
        description=desc,
        authorized_scope=scope,
        available_interfaces=(
            [i.strip() for i in interfaces.split(",") if i.strip()]
            if interfaces else []
        ),
        url=url or "",
        allow_insecure_tls=allow_insecure_tls,
    )
    configs = ctx.load_target_configs()
    configs[name] = config.model_dump(mode="json")
    ctx.save_target_configs(configs)
    click.echo(f"Target '{name}' registered (adapter={adapter}, type={target_type}).")
    if url:
        click.echo(f"  URL:         {url}")
    click.echo(f"  Environment: {env}")
    if scope:
        click.echo(f"  Scope:       {scope}")


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
    """Start a research session against a target adapter or saved target."""
    try:
        adapter = ctx.adapter_for(target)
    except (KeyError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    target_model = adapter.discover()
    policy = Policy(
        target_name=target_model.adapter,
        environment=target_model.environment or "*",
        scope=target_model.scope or "*",
        max_rounds=rounds,
        max_experiments=max_experiments,
        stop_on_finding=stop_on_finding,
    )
    engine = ctx.engine(policy)
    report = engine.research(adapter, rounds=rounds)

    click.echo("=== Research Report ===")
    if getattr(target_model, "rules", {}).get("base_url"):
        click.echo(f"URL:                  {target_model.rules['base_url']}")
        click.echo(f"Authorization scope:  {target_model.scope or '(operator-declared)'}")
    click.echo(f"Target:               {report.target_id}")
    click.echo(f"OpenSystem version:   {report.opensystem_version}")
    _echo_report(report)


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
    help="HTTP probe key to test (e.g. http-security-headers).",
)
@pass_ctx
def experiment_run(
    ctx: Context, target: str, hypothesis_statement: str, weakness: str | None
) -> None:
    """Run a single experiment against a target."""
    try:
        adapter = ctx.adapter_for(target)
    except (KeyError, ValueError) as e:
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
# journal
# --------------------------------------------------------------------------- #

@cli.group()
def journal() -> None:
    """Attack journal — every attack OpenSystem performed, in detail."""


@journal.command("list")
@click.option("--target", default=None, help="Filter by target ID.")
@click.option("--attack", "attack_key", default=None, help="Filter by attack key.")
@click.option("--password", default=None, help="Journal password (if locked).")
@pass_ctx
def journal_list(ctx: Context, target: str | None, attack_key: str | None,
                 password: str | None) -> None:
    """List journal entries."""
    from opensystem.journal.crypto import JournalLockedError
    from opensystem.journal.engine import JournalEngine

    engine = JournalEngine(ctx.store)
    try:
        entries = engine.list(target, attack_key, password=password)
    except JournalLockedError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    if not entries:
        click.echo("No journal entries.")
        return
    for e in entries:
        click.echo(
            f"[{e.outcome.value:12s}] {e.created_at.strftime('%Y-%m-%d %H:%M')} "
            f"| {e.attack_key} | {e.summary}"
        )


@journal.command("show")
@click.argument("entry_id")
@click.option("--password", default=None, help="Journal password (if locked).")
@pass_ctx
def journal_show(ctx: Context, entry_id: str, password: str | None) -> None:
    """Show a journal entry in full detail."""
    from opensystem.journal.crypto import JournalLockedError
    from opensystem.journal.engine import JournalEngine

    engine = JournalEngine(ctx.store)
    try:
        entries = engine.list(password=password)
        full_id = _resolve_prefix(entries, entry_id, "journal entry")
    except (JournalLockedError, click.ClickException) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    entry = engine.get(full_id, password=password)
    if entry is None:
        click.echo("Journal entry not found.", err=True)
        sys.exit(1)
    click.echo(f"# {entry.attack_name} ({entry.attack_key})")
    click.echo(f"Entry:     {entry.id}")
    click.echo(f"Target:    {entry.target_url or entry.target_id}")
    click.echo(f"Time:      {entry.created_at.isoformat()}")
    click.echo(f"Outcome:   {entry.outcome.value}")
    click.echo("")
    click.echo(entry.how_it_was_done)
    if entry.evidence_ids:
        click.echo("")
        click.echo("Evidence IDs:")
        for ev_id in entry.evidence_ids:
            click.echo(f"  - {ev_id}")


@journal.command("export")
@click.option("--target", default=None, help="Filter by target ID.")
@click.option("--output", "-o", default=None, help="Output file path.")
@click.option("--password", default=None, help="Journal password (if locked).")
@pass_ctx
def journal_export(ctx: Context, target: str | None, output: str | None,
                   password: str | None) -> None:
    """Export the journal as a detailed Markdown report."""
    from opensystem.journal.crypto import JournalLockedError
    from opensystem.journal.engine import JournalEngine

    try:
        markdown = JournalEngine(ctx.store).export_markdown(target, password=password)
    except JournalLockedError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    if output is None:
        click.echo(markdown)
        return
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown)
    click.echo(f"Journal exported to {out_path}")


@journal.command("lock")
@click.option("--password", prompt="Journal password", hide_input=True,
              confirmation_prompt=True, help="Password to encrypt the journal.")
@pass_ctx
def journal_lock(ctx: Context, password: str) -> None:
    """Encrypt the journal at rest with your password.

    After locking, all journal commands require --password to read content.
    The password is NOT stored — only a verifier. If you lose the password,
    the journal is permanently unreadable.
    """
    from opensystem.journal.engine import JournalEngine

    engine = JournalEngine(ctx.store)
    if engine.is_locked():
        click.echo("Journal is already locked.", err=True)
        sys.exit(1)
    count = engine.lock(password)
    click.echo(f"Journal locked: {count} entries encrypted at rest.")


@journal.command("unlock")
@click.option("--password", prompt="Journal password", hide_input=True,
              help="Password to decrypt the journal.")
@pass_ctx
def journal_unlock(ctx: Context, password: str) -> None:
    """Decrypt the journal back to plaintext.

    After unlocking, journal commands work without --password until the
    next lock. The decrypted entries are stored in plaintext in the
    database — only run this on a machine you trust.
    """
    from opensystem.journal.engine import JournalEngine

    engine = JournalEngine(ctx.store)
    if not engine.is_locked():
        click.echo("Journal is not locked.", err=True)
        sys.exit(1)
    if not engine.verify(password):
        click.echo("Wrong password.", err=True)
        sys.exit(1)
    count = engine.unlock(password)
    click.echo(f"Journal unlocked: {count} entries decrypted.")


@journal.command("status")
@pass_ctx
def journal_status(ctx: Context) -> None:
    """Show whether the journal is locked or unlocked."""
    from opensystem.journal.engine import JournalEngine

    engine = JournalEngine(ctx.store)
    if engine.is_locked():
        click.echo("Journal is LOCKED (encrypted at rest).")
        click.echo("Use 'opensystem journal unlock --password <pass>' to decrypt.")
    else:
        click.echo("Journal is UNLOCKED (plaintext).")
        click.echo("Use 'opensystem journal lock --password <pass>' to encrypt at rest.")


@journal.command("playbook")
@click.option("--attack", "attack_key", default=None,
              help="Show a single attack's methodology.")
@pass_ctx
def journal_playbook(ctx: Context, attack_key: str | None) -> None:
    """Show the documented methodology for every attack type."""
    from opensystem.journal.engine import JournalEngine

    click.echo(JournalEngine(ctx.store).playbook_markdown(attack_key))


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


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    cli()
