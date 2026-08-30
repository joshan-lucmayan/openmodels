"""Persistent knowledge store (Phase 10).

OpenSystem uses SQLite as its initial persistent store. This decision was
made because:

- SQLite is zero-configuration and built into Python's standard library.
- For single-instance, single-user deployments — the expected usage pattern
  during early development — SQLite is more than sufficient.
- It avoids external database-server dependencies.
- The schema is defined as pydantic model serialization, so migration to
  PostgreSQL or another backend is a matter of swapping the store
  implementation behind the same interface.

The store records everything: observations, hypotheses, experiments, evidence,
findings, defenses, regressions, knowledge, and evolution events. A future
attacker can ask questions like "What did we previously try?", "What failed?",
"What defense stopped it?", "What changed since then?".

Write semantics
---------------
Two intentional write policies exist (see ADR 005 for the integrity model):

- **Append-only** (audit/history records): ``INSERT ... ON CONFLICT(id) DO
  NOTHING``. The first version of a record wins; a repeated save can never
  silently overwrite history.
- **Upsert** (mutable state such as campaigns, findings status, targets):
  ``INSERT OR REPLACE`` with a stable id. Re-saving a mutated model is an
  intentional update.

Schema upgrades run through :data:`MIGRATIONS` — ordered, deterministic steps
keyed by schema version. Fresh databases receive the baseline schema directly;
existing databases are migrated step by step, additively, without destroying
data.
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from opensystem import VERSION
from opensystem.models import (
    Actor,
    ActorKind,
    AttackObjective,
    AttackPath,
    AttackSurface,
    Campaign,
    CampaignStatus,
    CaseStudy,
    Defense,
    Entitlement,
    Evidence,
    EvidenceKind,
    EvolutionEvent,
    EvolutionTrigger,
    Experiment,
    Finding,
    FindingStatus,
    Hypothesis,
    HypothesisStatus,
    ImpactVerification,
    InvariantStatus,
    Knowledge,
    KnowledgeKind,
    ObjectiveStatus,
    Observation,
    ProofSession,
    ProofSessionStatus,
    ProtectedResource,
    ProtectedResourceType,
    Regression,
    ResearchReport,
    SecurityInvariant,
    Severity,
    Target,
    TestOutcome,
    TestSpec,
)
from opensystem.version import SCHEMA_VERSION


def _j(data: Any) -> str:
    """Serialize a dict/list to JSON for storage."""
    return json.dumps(data, default=str)


def _uj(raw: str | None) -> Any:
    """Deserialize JSON; return empty dict on None or empty."""
    if not raw:
        return {}
    return json.loads(raw)


def _dt(raw: str) -> datetime.datetime:
    """Parse an ISO-8601 timestamp stored as TEXT."""
    return datetime.datetime.fromisoformat(raw)


def _opt_dt(raw: str | None) -> datetime.datetime | None:
    """Parse an optional ISO-8601 timestamp stored as TEXT."""
    return _dt(raw) if raw else None


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _parse_legacy_component(component: str) -> tuple[str, str, str] | None:
    """Parse a legacy ``affected_component`` display string.

    Legacy campaign findings formatted the attack path as::

        actor=KIND/name → interface=[iface] → resource=name

    Returns (actor_name, interface, resource_name), or None if the string
    does not match the legacy format. Unparseable strings are never guessed
    at: structured identity fields are simply left empty.
    """
    parts = [p.strip() for p in (component or "").split("→")]
    if len(parts) != 3:
        return None
    actor_part, interface_part, resource_part = parts
    if not (
        actor_part.startswith("actor=")
        and interface_part.startswith("interface=")
        and resource_part.startswith("resource=")
    ):
        return None
    actor_name = actor_part.split("=", 1)[1].split("/")[-1].strip()
    interface = interface_part.split("=", 1)[1].strip(" []")
    resource_name = resource_part.split("=", 1)[1].strip()
    if not actor_name or not interface or not resource_name:
        return None
    return actor_name, interface, resource_name


def _backfill_finding_identities(conn: sqlite3.Connection) -> None:
    """Best-effort backfill of structured identities on legacy findings.

    Only identities that can be resolved against persisted actors and
    protected resources are filled; everything else stays empty and the
    original display string is preserved untouched.
    """
    rows = conn.execute(
        "SELECT id, affected_component FROM findings "
        "WHERE actor_id IS NULL AND affected_component != ''"
    ).fetchall()
    for finding_id, component in rows:
        parsed = _parse_legacy_component(component)
        if parsed is None:
            continue
        actor_name, interface, resource_name = parsed
        conn.execute(
            "UPDATE findings SET interface = ? WHERE id = ?",
            (interface, finding_id),
        )
        actor = conn.execute(
            "SELECT id FROM actors WHERE name = ?", (actor_name,)
        ).fetchone()
        resource = conn.execute(
            "SELECT id FROM protected_resources WHERE name = ?", (resource_name,)
        ).fetchone()
        if actor is not None:
            conn.execute(
                "UPDATE findings SET actor_id = ? WHERE id = ?",
                (actor["id"], finding_id),
            )
        if resource is not None:
            conn.execute(
                "UPDATE findings SET resource_id = ? WHERE id = ?",
                (resource["id"], finding_id),
            )


def _migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
    """v0.2 → v0.3: impact verifications, proof sessions, case studies."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS impact_verifications (
            id          TEXT PRIMARY KEY,
            finding_id  TEXT NOT NULL,
            verifier    TEXT DEFAULT 'ImpactVerifier',
            verified    INTEGER NOT NULL DEFAULT 0,
            method      TEXT DEFAULT '',
            detail      TEXT DEFAULT '{}',
            verified_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS proof_sessions (
            id               TEXT PRIMARY KEY,
            finding_id       TEXT NOT NULL,
            campaign_id      TEXT DEFAULT '',
            target_id        TEXT NOT NULL,
            target_adapter   TEXT DEFAULT '',
            actor_id         TEXT NOT NULL,
            resource_id      TEXT NOT NULL,
            username         TEXT DEFAULT '',
            key_hash         TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'ACTIVE',
            created_at       TEXT NOT NULL,
            expires_at       TEXT NOT NULL,
            revoked_at       TEXT,
            last_used_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS case_studies (
            id          TEXT PRIMARY KEY,
            finding_id  TEXT NOT NULL,
            title       TEXT DEFAULT '',
            body        TEXT DEFAULT '{}',
            created_at  TEXT NOT NULL
        );
        """
    )


def _migrate_v2_to_v3(conn: sqlite3.Connection) -> None:
    """v0.3 → v0.3.1: structured finding identities + campaign-linked paths.

    Additive only. Legacy findings get a best-effort backfill of their
    structured identities; unresolvable ones keep empty fields. Targets
    gain declared environment/scope columns (left empty for legacy rows —
    undeclared scopes fail closed in policy matching).
    """
    findings_cols = _table_columns(conn, "findings")
    for column in ("objective_id", "actor_id", "resource_id", "interface"):
        if column not in findings_cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT")

    path_cols = _table_columns(conn, "attack_paths")
    if "campaign_id" not in path_cols:
        conn.execute(
            "ALTER TABLE attack_paths ADD COLUMN campaign_id TEXT DEFAULT ''"
        )

    target_cols = _table_columns(conn, "targets")
    for column in ("environment", "scope"):
        if column not in target_cols:
            conn.execute(
                f"ALTER TABLE targets ADD COLUMN {column} TEXT DEFAULT ''"
            )

    conn.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_findings_boundary
            ON findings(target_id, actor_id, resource_id, interface);
        CREATE INDEX IF NOT EXISTS idx_attack_paths_campaign
            ON attack_paths(campaign_id);
        """
    )
    _backfill_finding_identities(conn)


MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    2: _migrate_v1_to_v2,
    3: _migrate_v2_to_v3,
}


class KnowledgeStore:
    """SQLite-backed persistent store for the OpenSystem research graph.

    Every public method accepts model instances and returns lists of model
    instances. The SQLite details are an implementation concern.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._conn: sqlite3.Connection | None = None
        self._txn_depth = 0
        self._ensure_schema()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------ #
    # Transactions
    # ------------------------------------------------------------------ #

    @contextmanager
    def transaction(self) -> Iterator[KnowledgeStore]:
        """Group saves into one atomic unit of work.

        Saves issued inside the block are committed together when the block
        exits, and rolled back if it raises. Nesting is supported; only the
        outermost block commits or rolls back.
        """
        self._txn_depth += 1
        try:
            yield self
        except BaseException:
            self._txn_depth -= 1
            if self._txn_depth == 0:
                self._conn.rollback()
            raise
        else:
            self._txn_depth -= 1
            if self._txn_depth == 0:
                self._conn.commit()

    def _commit(self) -> None:
        """Commit unless inside an open transaction block."""
        if self._txn_depth == 0:
            self._conn.commit()

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #

    def _ensure_schema(self) -> None:
        first = not os.path.exists(self._path)
        self._conn = sqlite3.connect(self._path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.row_factory = sqlite3.Row

        (version,) = self._conn.execute("PRAGMA user_version").fetchone()
        if first or version == 0:
            self._create_baseline()
        elif version < SCHEMA_VERSION:
            self._run_migrations(version)
        if first:
            self._conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ("created_at", _now()),
            )
            self._conn.commit()

    def _run_migrations(self, current: int) -> None:
        """Apply pending migrations sequentially, oldest first."""
        for version in range(current + 1, SCHEMA_VERSION + 1):
            migration = MIGRATIONS.get(version)
            if migration is None:
                raise RuntimeError(
                    f"No migration registered for schema version {version}."
                )
            migration(self._conn)
            self._conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ("schema_version", str(version)),
            )
            self._conn.execute(f"PRAGMA user_version = {int(version)}")
            self._conn.commit()

    def _create_baseline(self) -> None:
        sql = """
        CREATE TABLE IF NOT EXISTS metadata (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS targets (
            id             TEXT PRIMARY KEY,
            name           TEXT NOT NULL,
            kind           TEXT NOT NULL DEFAULT 'generic',
            adapter        TEXT NOT NULL,
            description    TEXT DEFAULT '',
            version        TEXT DEFAULT '0.0.0',
            assets         TEXT DEFAULT '[]',
            interfaces     TEXT DEFAULT '[]',
            trust_boundaries TEXT DEFAULT '[]',
            rules          TEXT DEFAULT '{}',
            environment    TEXT DEFAULT '',
            scope          TEXT DEFAULT '',
            created_at     TEXT NOT NULL,
            updated_at     TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS observations (
            id         TEXT PRIMARY KEY,
            target_id  TEXT NOT NULL,
            interface  TEXT DEFAULT '',
            data       TEXT DEFAULT '{}',
            source     TEXT DEFAULT '',
            timestamp  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hypotheses (
            id          TEXT PRIMARY KEY,
            target_id   TEXT NOT NULL,
            statement   TEXT NOT NULL,
            assumption  TEXT DEFAULT '',
            status      TEXT NOT NULL DEFAULT 'PROPOSED',
            parent_id   TEXT,
            origin      TEXT DEFAULT 'manual',
            confidence  REAL DEFAULT 0.5,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS experiments (
            id                TEXT PRIMARY KEY,
            hypothesis_id     TEXT NOT NULL,
            target_id         TEXT NOT NULL,
            opensystem_version TEXT NOT NULL,
            test_name         TEXT DEFAULT '',
            test_description  TEXT DEFAULT '',
            test_parameters   TEXT DEFAULT '{}',
            expected_outcome  TEXT DEFAULT 'SUCCESS',
            expected_result   TEXT DEFAULT '',
            observed_result   TEXT DEFAULT '',
            outcome           TEXT NOT NULL DEFAULT 'INCONCLUSIVE',
            conclusion        TEXT DEFAULT '',
            next_hypothesis_id TEXT,
            evidence_ids      TEXT DEFAULT '[]',
            started_at        TEXT NOT NULL,
            completed_at      TEXT
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id             TEXT PRIMARY KEY,
            experiment_id  TEXT,
            kind           TEXT NOT NULL DEFAULT 'OBSERVATION',
            data           TEXT DEFAULT '{}',
            reference      TEXT DEFAULT '',
            captured_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id                   TEXT PRIMARY KEY,
            target_id            TEXT NOT NULL,
            hypothesis_id        TEXT,
            objective_id         TEXT,
            actor_id             TEXT,
            resource_id          TEXT,
            interface            TEXT,
            severity             TEXT NOT NULL DEFAULT 'MEDIUM',
            affected_component   TEXT DEFAULT '',
            attack_hypothesis    TEXT DEFAULT '',
            observed_behavior    TEXT DEFAULT '',
            evidence_ids         TEXT DEFAULT '[]',
            impact               TEXT DEFAULT '',
            reproduction         TEXT DEFAULT '',
            recommended_mitigation TEXT DEFAULT '',
            verification_status  TEXT NOT NULL DEFAULT 'DISCOVERED',
            created_at           TEXT NOT NULL,
            updated_at           TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS defenses (
            id                  TEXT PRIMARY KEY,
            finding_id          TEXT NOT NULL,
            description         TEXT NOT NULL,
            verification_status TEXT NOT NULL DEFAULT 'MITIGATION',
            applied_at          TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS regressions (
            id             TEXT PRIMARY KEY,
            defense_id     TEXT NOT NULL,
            hypothesis_id  TEXT NOT NULL,
            target_id      TEXT NOT NULL,
            outcome        TEXT NOT NULL,
            detail         TEXT DEFAULT '',
            created_at     TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS knowledge (
            id          TEXT PRIMARY KEY,
            kind        TEXT NOT NULL,
            content     TEXT NOT NULL,
            target_id   TEXT,
            provenance  TEXT DEFAULT '',
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evolution_events (
            id                  TEXT PRIMARY KEY,
            trigger             TEXT NOT NULL,
            reason              TEXT NOT NULL,
            from_hypothesis_id  TEXT,
            to_hypothesis_id    TEXT,
            provenance          TEXT DEFAULT '',
            created_at          TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS protected_resources (
            id             TEXT PRIMARY KEY,
            name           TEXT NOT NULL,
            resource_type  TEXT NOT NULL,
            value          TEXT DEFAULT '',
            description    TEXT DEFAULT '',
            interfaces     TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS actors (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            kind         TEXT NOT NULL,
            description  TEXT DEFAULT '',
            entitlements TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS entitlements (
            id          TEXT PRIMARY KEY,
            actor_id    TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            action      TEXT DEFAULT 'access'
        );

        CREATE TABLE IF NOT EXISTS security_invariants (
            id               TEXT PRIMARY KEY,
            actor_id         TEXT NOT NULL,
            resource_id      TEXT NOT NULL,
            forbidden_action TEXT DEFAULT 'access',
            statement        TEXT DEFAULT '',
            status           TEXT NOT NULL DEFAULT 'UNTESTED'
        );

        CREATE TABLE IF NOT EXISTS attack_objectives (
            id                   TEXT PRIMARY KEY,
            campaign_id          TEXT NOT NULL,
            actor_id             TEXT NOT NULL,
            resource_id          TEXT NOT NULL,
            security_invariant_id TEXT NOT NULL,
            success_condition    TEXT DEFAULT '',
            status               TEXT NOT NULL DEFAULT 'FORMULATED'
        );

        CREATE TABLE IF NOT EXISTS campaigns (
            id               TEXT PRIMARY KEY,
            name             TEXT NOT NULL,
            target_id        TEXT NOT NULL,
            target_adapter   TEXT DEFAULT '',
            description      TEXT DEFAULT '',
            actor_ids        TEXT DEFAULT '[]',
            resource_ids     TEXT DEFAULT '[]',
            objective_ids    TEXT DEFAULT '[]',
            invariant_ids    TEXT DEFAULT '[]',
            status           TEXT NOT NULL DEFAULT 'CREATED',
            created_at       TEXT NOT NULL,
            started_at       TEXT,
            completed_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS attack_surfaces (
            id            TEXT PRIMARY KEY,
            target_id     TEXT NOT NULL,
            interfaces    TEXT DEFAULT '[]',
            resources     TEXT DEFAULT '[]',
            auth_states   TEXT DEFAULT '[]',
            transitions   TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS attack_paths (
            id          TEXT PRIMARY KEY,
            campaign_id TEXT DEFAULT '',
            actor_id    TEXT NOT NULL,
            interface   TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            operation   TEXT DEFAULT 'access',
            outcome     TEXT NOT NULL DEFAULT 'INCONCLUSIVE'
        );

        CREATE TABLE IF NOT EXISTS impact_verifications (
            id          TEXT PRIMARY KEY,
            finding_id  TEXT NOT NULL,
            verifier    TEXT DEFAULT 'ImpactVerifier',
            verified    INTEGER NOT NULL DEFAULT 0,
            method      TEXT DEFAULT '',
            detail      TEXT DEFAULT '{}',
            verified_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS proof_sessions (
            id               TEXT PRIMARY KEY,
            finding_id       TEXT NOT NULL,
            campaign_id      TEXT DEFAULT '',
            target_id        TEXT NOT NULL,
            target_adapter   TEXT DEFAULT '',
            actor_id         TEXT NOT NULL,
            resource_id      TEXT NOT NULL,
            username         TEXT DEFAULT '',
            key_hash         TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'ACTIVE',
            created_at       TEXT NOT NULL,
            expires_at       TEXT NOT NULL,
            revoked_at       TEXT,
            last_used_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS case_studies (
            id          TEXT PRIMARY KEY,
            finding_id  TEXT NOT NULL,
            title       TEXT DEFAULT '',
            body        TEXT DEFAULT '{}',
            created_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_hypotheses_target ON hypotheses(target_id);
        CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(status);
        CREATE INDEX IF NOT EXISTS idx_experiments_hypothesis ON experiments(hypothesis_id);
        CREATE INDEX IF NOT EXISTS idx_experiments_target ON experiments(target_id);
        CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(verification_status);
        CREATE INDEX IF NOT EXISTS idx_findings_boundary
            ON findings(target_id, actor_id, resource_id, interface);
        CREATE INDEX IF NOT EXISTS idx_knowledge_target ON knowledge(target_id);
        CREATE INDEX IF NOT EXISTS idx_knowledge_kind ON knowledge(kind);
        CREATE INDEX IF NOT EXISTS idx_attack_paths_campaign
            ON attack_paths(campaign_id);
        """
        self._conn.executescript(sql)
        self._conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("opensystem_version", VERSION),
        )
        self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self._conn.commit()

    # ------------------------------------------------------------------ #
    # Serialization helpers
    # ------------------------------------------------------------------ #

    def _row_to_target(self, r: sqlite3.Row) -> Target:
        return Target(
            id=r["id"],
            name=r["name"],
            kind=r["kind"],
            adapter=r["adapter"],
            description=r["description"],
            version=r["version"],
            assets=_uj(r["assets"]),
            interfaces=_uj(r["interfaces"]),
            trust_boundaries=_uj(r["trust_boundaries"]),
            rules=_uj(r["rules"]),
            environment=r["environment"],
            scope=r["scope"],
            created_at=_dt(r["created_at"]),
            updated_at=_dt(r["updated_at"]),
        )

    def _target_to_row(self, t: Target) -> dict:
        return {
            "id": t.id,
            "name": t.name,
            "kind": t.kind,
            "adapter": t.adapter,
            "description": t.description,
            "version": t.version,
            "assets": _j(t.assets),
            "interfaces": _j(t.interfaces),
            "trust_boundaries": _j(t.trust_boundaries),
            "rules": _j(t.rules),
            "environment": t.environment,
            "scope": t.scope,
            "created_at": t.created_at.isoformat(),
            "updated_at": t.updated_at.isoformat(),
        }

    # ------------------------------------------------------------------ #
    # CRUD — Targets
    # ------------------------------------------------------------------ #

    def save_target(self, target: Target) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO targets
               (id, name, kind, adapter, description, version, assets,
                interfaces, trust_boundaries, rules, environment, scope,
                created_at, updated_at)
               VALUES (:id, :name, :kind, :adapter, :description, :version,
                :assets, :interfaces, :trust_boundaries, :rules,
                :environment, :scope, :created_at, :updated_at)""",
            self._target_to_row(target),
        )
        self._commit()

    def get_target(self, target_id: str) -> Target | None:
        cur = self._conn.execute(
            "SELECT * FROM targets WHERE id = ?", (target_id,)
        )
        r = cur.fetchone()
        return self._row_to_target(r) if r else None

    def list_targets(self) -> list[Target]:
        cur = self._conn.execute("SELECT * FROM targets ORDER BY name")
        return [self._row_to_target(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------ #
    # CRUD — Observations
    # ------------------------------------------------------------------ #

    def save_observation(self, obs: Observation) -> None:
        self._conn.execute(
            "INSERT INTO observations "
            "(id, target_id, interface, data, source, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (obs.id, obs.target_id, obs.interface, _j(obs.data),
             obs.source, obs.timestamp.isoformat()),
        )
        self._commit()

    def save_observations(self, obs_list: list[Observation]) -> None:
        with self.transaction():
            for obs in obs_list:
                self.save_observation(obs)

    def list_observations(self, target_id: str) -> list[Observation]:
        cur = self._conn.execute(
            "SELECT * FROM observations WHERE target_id = ? ORDER BY timestamp",
            (target_id,),
        )
        return [
            Observation(
                id=r["id"],
                target_id=r["target_id"],
                interface=r["interface"],
                data=_uj(r["data"]),
                source=r["source"],
                timestamp=_dt(r["timestamp"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # CRUD — Hypotheses
    # ------------------------------------------------------------------ #

    def save_hypothesis(self, h: Hypothesis) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO hypotheses "
            "(id, target_id, statement, assumption, status, parent_id, "
            " origin, confidence, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (h.id, h.target_id, h.statement, h.assumption, h.status.value,
             h.parent_id, h.origin, h.confidence,
             h.created_at.isoformat(), h.updated_at.isoformat()),
        )
        self._commit()

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        cur = self._conn.execute(
            "SELECT * FROM hypotheses WHERE id = ?", (hypothesis_id,)
        )
        r = cur.fetchone()
        return self._row_to_hypothesis(r) if r else None

    def _row_to_hypothesis(self, r: sqlite3.Row) -> Hypothesis:
        return Hypothesis(
            id=r["id"],
            target_id=r["target_id"],
            statement=r["statement"],
            assumption=r["assumption"],
            status=HypothesisStatus(r["status"]),
            parent_id=r["parent_id"],
            origin=r["origin"],
            confidence=r["confidence"],
            created_at=_dt(r["created_at"]),
            updated_at=_dt(r["updated_at"]),
        )

    def list_hypotheses(self, target_id: str) -> list[Hypothesis]:
        cur = self._conn.execute(
            "SELECT * FROM hypotheses WHERE target_id = ? ORDER BY created_at",
            (target_id,),
        )
        return [self._row_to_hypothesis(r) for r in cur.fetchall()]

    def update_hypothesis_status(self, hypothesis_id: str, status: HypothesisStatus) -> None:
        self._conn.execute(
            "UPDATE hypotheses SET status = ?, updated_at = ? WHERE id = ?",
            (status.value, _now(), hypothesis_id),
        )
        self._commit()

    # ------------------------------------------------------------------ #
    # CRUD — Experiments
    # ------------------------------------------------------------------ #

    def save_experiment(self, e: Experiment) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO experiments
               (id, hypothesis_id, target_id, opensystem_version,
                test_name, test_description, test_parameters,
                expected_outcome, expected_result, observed_result,
                outcome, conclusion, next_hypothesis_id, evidence_ids,
                started_at, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                e.id, e.hypothesis_id, e.target_id, e.opensystem_version,
                e.test.name, e.test.description, _j(e.test.parameters),
                e.test.expected_outcome.value, e.expected_result,
                e.observed_result, e.outcome.value, e.conclusion,
                e.next_hypothesis_id, _j(e.evidence_ids),
                e.started_at.isoformat(),
                e.completed_at.isoformat() if e.completed_at else None,
            ),
        )
        self._commit()

    def _row_to_experiment(self, r: sqlite3.Row) -> Experiment:
        return Experiment(
            id=r["id"],
            hypothesis_id=r["hypothesis_id"],
            target_id=r["target_id"],
            opensystem_version=r["opensystem_version"],
            test=TestSpec(
                name=r["test_name"],
                description=r["test_description"],
                parameters=_uj(r["test_parameters"]),
                expected_outcome=TestOutcome(r["expected_outcome"]),
            ),
            expected_result=r["expected_result"],
            observed_result=r["observed_result"],
            outcome=TestOutcome(r["outcome"]),
            conclusion=r["conclusion"],
            next_hypothesis_id=r["next_hypothesis_id"],
            evidence_ids=_uj(r["evidence_ids"]),
            started_at=_dt(r["started_at"]),
            completed_at=_opt_dt(r["completed_at"]),
        )

    def list_experiments(self, target_id: str) -> list[Experiment]:
        cur = self._conn.execute(
            "SELECT * FROM experiments WHERE target_id = ? ORDER BY started_at",
            (target_id,),
        )
        return [self._row_to_experiment(r) for r in cur.fetchall()]

    def get_experiments_by_hypothesis(self, hypothesis_id: str) -> list[Experiment]:
        cur = self._conn.execute(
            "SELECT * FROM experiments WHERE hypothesis_id = ? ORDER BY started_at",
            (hypothesis_id,),
        )
        return [self._row_to_experiment(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------ #
    # CRUD — Evidence
    # ------------------------------------------------------------------ #

    def save_evidence(self, e: Evidence) -> None:
        self._conn.execute(
            "INSERT INTO evidence "
            "(id, experiment_id, kind, data, reference, captured_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (e.id, e.experiment_id, e.kind.value, _j(e.data),
             e.reference, e.captured_at.isoformat()),
        )
        self._commit()

    def save_evidence_list(self, ev_list: list[Evidence]) -> None:
        with self.transaction():
            for e in ev_list:
                self.save_evidence(e)

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        cur = self._conn.execute(
            "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
        )
        r = cur.fetchone()
        if r is None:
            return None
        return Evidence(
            id=r["id"],
            experiment_id=r["experiment_id"],
            kind=EvidenceKind(r["kind"]),
            data=_uj(r["data"]),
            reference=r["reference"],
            captured_at=_dt(r["captured_at"]),
        )

    # ------------------------------------------------------------------ #
    # CRUD — Findings
    # ------------------------------------------------------------------ #

    def save_finding(self, f: Finding) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO findings
               (id, target_id, hypothesis_id, objective_id, actor_id,
                resource_id, interface, severity, affected_component,
                attack_hypothesis, observed_behavior, evidence_ids, impact,
                reproduction, recommended_mitigation, verification_status,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f.id, f.target_id, f.hypothesis_id, f.objective_id,
                f.actor_id, f.resource_id, f.interface, f.severity.value,
                f.affected_component, f.attack_hypothesis,
                f.observed_behavior, _j(f.evidence_ids), f.impact,
                f.reproduction, f.recommended_mitigation,
                f.verification_status.value,
                f.created_at.isoformat(), f.updated_at.isoformat(),
            ),
        )
        self._commit()

    def _row_to_finding(self, r: sqlite3.Row) -> Finding:
        return Finding(
            id=r["id"],
            target_id=r["target_id"],
            hypothesis_id=r["hypothesis_id"],
            objective_id=r["objective_id"],
            actor_id=r["actor_id"],
            resource_id=r["resource_id"],
            interface=r["interface"],
            severity=Severity(r["severity"]),
            affected_component=r["affected_component"],
            attack_hypothesis=r["attack_hypothesis"],
            observed_behavior=r["observed_behavior"],
            evidence_ids=_uj(r["evidence_ids"]),
            impact=r["impact"],
            reproduction=r["reproduction"],
            recommended_mitigation=r["recommended_mitigation"],
            verification_status=FindingStatus(r["verification_status"]),
            created_at=_dt(r["created_at"]),
            updated_at=_dt(r["updated_at"]),
        )

    def get_finding(self, finding_id: str) -> Finding | None:
        cur = self._conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        )
        r = cur.fetchone()
        return self._row_to_finding(r) if r else None

    def list_findings(self, target_id: str | None = None) -> list[Finding]:
        if target_id:
            cur = self._conn.execute(
                "SELECT * FROM findings WHERE target_id = ? ORDER BY created_at",
                (target_id,),
            )
        else:
            cur = self._conn.execute(
                "SELECT * FROM findings ORDER BY created_at"
            )
        return [self._row_to_finding(r) for r in cur.fetchall()]

    def find_open_boundary_finding(
        self,
        target_id: str,
        actor_id: str,
        resource_id: str,
        interface: str,
    ) -> Finding | None:
        """Return the open finding for a violated boundary identity, if any.

        The identity is (target, actor, resource, interface) — the
        deduplication key for campaign findings. Legacy findings without
        structured identities never match (SQL NULL comparison): they cannot
        be reliably deduplicated and are left alone.
        """
        cur = self._conn.execute(
            """SELECT * FROM findings
               WHERE target_id = ? AND actor_id = ? AND resource_id = ?
                 AND interface = ? AND verification_status != ?
               ORDER BY created_at
               LIMIT 1""",
            (target_id, actor_id, resource_id, interface,
             FindingStatus.CLOSED.value),
        )
        r = cur.fetchone()
        return self._row_to_finding(r) if r else None

    def update_finding_status(self, finding_id: str, status: FindingStatus) -> None:
        self._conn.execute(
            "UPDATE findings SET verification_status = ?, updated_at = ? WHERE id = ?",
            (status.value, _now(), finding_id),
        )
        self._commit()

    # ------------------------------------------------------------------ #
    # CRUD — Defenses
    # ------------------------------------------------------------------ #

    def save_defense(self, d: Defense) -> None:
        self._conn.execute(
            "INSERT INTO defenses "
            "(id, finding_id, description, verification_status, applied_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (d.id, d.finding_id, d.description, d.verification_status.value,
             d.applied_at.isoformat()),
        )
        self._commit()

    def list_defenses(self, finding_id: str | None = None) -> list[Defense]:
        if finding_id:
            cur = self._conn.execute(
                "SELECT * FROM defenses WHERE finding_id = ? ORDER BY applied_at",
                (finding_id,),
            )
        else:
            cur = self._conn.execute(
                "SELECT * FROM defenses ORDER BY applied_at"
            )
        return [
            Defense(
                id=r["id"],
                finding_id=r["finding_id"],
                description=r["description"],
                verification_status=FindingStatus(r["verification_status"]),
                applied_at=_dt(r["applied_at"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # CRUD — Regressions
    # ------------------------------------------------------------------ #

    def save_regression(self, r: Regression) -> None:
        self._conn.execute(
            "INSERT INTO regressions "
            "(id, defense_id, hypothesis_id, target_id, outcome, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (r.id, r.defense_id, r.hypothesis_id, r.target_id,
             r.outcome.value, r.detail, r.created_at.isoformat()),
        )
        self._commit()

    def list_regressions(self, target_id: str | None = None) -> list[Regression]:
        if target_id:
            cur = self._conn.execute(
                "SELECT * FROM regressions WHERE target_id = ? ORDER BY created_at",
                (target_id,),
            )
        else:
            cur = self._conn.execute(
                "SELECT * FROM regressions ORDER BY created_at"
            )
        return [
            Regression(
                id=r["id"],
                defense_id=r["defense_id"],
                hypothesis_id=r["hypothesis_id"],
                target_id=r["target_id"],
                outcome=TestOutcome(r["outcome"]),
                detail=r["detail"],
                created_at=_dt(r["created_at"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # CRUD — Knowledge
    # ------------------------------------------------------------------ #

    def save_knowledge(self, k: Knowledge) -> None:
        self._conn.execute(
            "INSERT INTO knowledge "
            "(id, kind, content, target_id, provenance, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (k.id, k.kind.value, k.content, k.target_id,
             k.provenance, k.created_at.isoformat()),
        )
        self._commit()

    def search_knowledge(self, query: str, target_id: str | None = None) -> list[Knowledge]:
        like = f"%{query}%"
        if target_id:
            cur = self._conn.execute(
                "SELECT * FROM knowledge "
                "WHERE target_id = ? AND (content LIKE ? OR kind LIKE ?) "
                "ORDER BY created_at",
                (target_id, like, like),
            )
        else:
            cur = self._conn.execute(
                "SELECT * FROM knowledge WHERE content LIKE ? OR kind LIKE ? "
                "ORDER BY created_at",
                (like, like),
            )
        return [
            Knowledge(
                id=r["id"],
                kind=KnowledgeKind(r["kind"]),
                content=r["content"],
                target_id=r["target_id"],
                provenance=r["provenance"],
                created_at=_dt(r["created_at"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # CRUD — Evolution Events
    # ------------------------------------------------------------------ #

    def save_evolution_event(self, ev: EvolutionEvent) -> None:
        self._conn.execute(
            "INSERT INTO evolution_events "
            "(id, trigger, reason, from_hypothesis_id, to_hypothesis_id, "
            " provenance, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (ev.id, ev.trigger.value, ev.reason, ev.from_hypothesis_id,
             ev.to_hypothesis_id, ev.provenance, ev.created_at.isoformat()),
        )
        self._commit()

    def list_evolution_events(self, target_id: str | None = None) -> list[EvolutionEvent]:
        if target_id:
            cur = self._conn.execute(
                """SELECT * FROM evolution_events WHERE id IN (
                   SELECT id FROM evolution_events
                   WHERE from_hypothesis_id IN (
                       SELECT id FROM hypotheses WHERE target_id = ?
                   )
                ) ORDER BY created_at""",
                (target_id,),
            )
        else:
            cur = self._conn.execute(
                "SELECT * FROM evolution_events ORDER BY created_at"
            )
        return [
            EvolutionEvent(
                id=r["id"],
                trigger=EvolutionTrigger(r["trigger"]),
                reason=r["reason"],
                from_hypothesis_id=r["from_hypothesis_id"],
                to_hypothesis_id=r["to_hypothesis_id"],
                provenance=r["provenance"],
                created_at=_dt(r["created_at"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # CRUD — Campaign entities
    # ------------------------------------------------------------------ #

    def save_protected_resource(self, r: ProtectedResource) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO protected_resources "
            "(id, name, resource_type, value, description, interfaces) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (r.id, r.name, r.resource_type.value, r.value,
             r.description, _j(r.interfaces)),
        )
        self._commit()

    def save_actor(self, a: Actor) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO actors "
            "(id, name, kind, description, entitlements) VALUES (?, ?, ?, ?, ?)",
            (a.id, a.name, a.kind.value, a.description, _j(a.entitlements)),
        )
        self._commit()

    def get_actor(self, actor_id: str) -> Actor | None:
        cur = self._conn.execute("SELECT * FROM actors WHERE id = ?", (actor_id,))
        r = cur.fetchone()
        if r is None:
            return None
        return Actor(
            id=r["id"],
            name=r["name"],
            kind=ActorKind(r["kind"]),
            description=r["description"],
            entitlements=_uj(r["entitlements"]),
        )

    def list_actors(self) -> list[Actor]:
        cur = self._conn.execute("SELECT * FROM actors ORDER BY name")
        return [
            Actor(
                id=r["id"],
                name=r["name"],
                kind=ActorKind(r["kind"]),
                description=r["description"],
                entitlements=_uj(r["entitlements"]),
            )
            for r in cur.fetchall()
        ]

    def get_protected_resource(self, resource_id: str) -> ProtectedResource | None:
        cur = self._conn.execute(
            "SELECT * FROM protected_resources WHERE id = ?", (resource_id,)
        )
        r = cur.fetchone()
        if r is None:
            return None
        return ProtectedResource(
            id=r["id"],
            name=r["name"],
            resource_type=ProtectedResourceType(r["resource_type"]),
            value=r["value"],
            description=r["description"],
            interfaces=_uj(r["interfaces"]),
        )

    def save_entitlement(self, e: Entitlement) -> None:
        self._conn.execute(
            "INSERT INTO entitlements "
            "(id, actor_id, resource_id, action) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (e.id, e.actor_id, e.resource_id, e.action),
        )
        self._commit()

    def save_invariant(self, inv: SecurityInvariant) -> None:
        self._conn.execute(
            "INSERT INTO security_invariants "
            "(id, actor_id, resource_id, forbidden_action, statement, status) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (inv.id, inv.actor_id, inv.resource_id, inv.forbidden_action,
             inv.statement, inv.status.value),
        )
        self._commit()

    def update_invariant_status(self, invariant_id: str, status: InvariantStatus) -> None:
        self._conn.execute(
            "UPDATE security_invariants SET status = ? WHERE id = ?",
            (status.value, invariant_id),
        )
        self._commit()

    def save_objective(self, o: AttackObjective) -> None:
        self._conn.execute(
            "INSERT INTO attack_objectives "
            "(id, campaign_id, actor_id, resource_id, security_invariant_id, "
            " success_condition, status) VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (o.id, o.campaign_id, o.actor_id, o.resource_id,
             o.security_invariant_id, o.success_condition, o.status.value),
        )
        self._commit()

    def update_objective_status(self, objective_id: str, status: ObjectiveStatus) -> None:
        self._conn.execute(
            "UPDATE attack_objectives SET status = ? WHERE id = ?",
            (status.value, objective_id),
        )
        self._commit()

    def list_objectives(self, campaign_id: str) -> list[AttackObjective]:
        cur = self._conn.execute(
            "SELECT * FROM attack_objectives WHERE campaign_id = ?",
            (campaign_id,),
        )
        return [
            AttackObjective(
                id=r["id"],
                campaign_id=r["campaign_id"],
                actor_id=r["actor_id"],
                resource_id=r["resource_id"],
                security_invariant_id=r["security_invariant_id"],
                success_condition=r["success_condition"],
                status=ObjectiveStatus(r["status"]),
            )
            for r in cur.fetchall()
        ]

    def save_campaign(self, c: Campaign) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO campaigns "
            "(id, name, target_id, target_adapter, description, actor_ids, "
            " resource_ids, objective_ids, invariant_ids, status, created_at, "
            " started_at, completed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (c.id, c.name, c.target_id, c.target_adapter, c.description,
             _j(c.actor_ids), _j(c.resource_ids), _j(c.objective_ids),
             _j(c.invariant_ids), c.status.value, c.created_at.isoformat(),
             c.started_at.isoformat() if c.started_at else None,
             c.completed_at.isoformat() if c.completed_at else None),
        )
        self._commit()

    def _row_to_campaign(self, r: sqlite3.Row) -> Campaign:
        return Campaign(
            id=r["id"],
            name=r["name"],
            target_id=r["target_id"],
            target_adapter=r["target_adapter"],
            description=r["description"],
            actor_ids=_uj(r["actor_ids"]),
            resource_ids=_uj(r["resource_ids"]),
            objective_ids=_uj(r["objective_ids"]),
            invariant_ids=_uj(r["invariant_ids"]),
            status=CampaignStatus(r["status"]),
            created_at=_dt(r["created_at"]),
            started_at=_opt_dt(r["started_at"]),
            completed_at=_opt_dt(r["completed_at"]),
        )

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        cur = self._conn.execute(
            "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
        )
        r = cur.fetchone()
        if r is None:
            return None
        return self._row_to_campaign(r)

    def list_campaigns(self) -> list[Campaign]:
        cur = self._conn.execute("SELECT * FROM campaigns ORDER BY created_at")
        return [self._row_to_campaign(r) for r in cur.fetchall()]

    def save_attack_surface(self, s: AttackSurface) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO attack_surfaces "
            "(id, target_id, interfaces, resources, auth_states, transitions) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (s.id, s.target_id, _j(s.interfaces), _j(s.resources),
             _j(s.auth_states), _j(s.transitions)),
        )
        self._commit()

    def get_attack_surface(self, target_id: str) -> AttackSurface | None:
        cur = self._conn.execute(
            "SELECT * FROM attack_surfaces WHERE target_id = ?",
            (target_id,),
        )
        r = cur.fetchone()
        if r is None:
            return None
        return AttackSurface(
            id=r["id"],
            target_id=r["target_id"],
            interfaces=_uj(r["interfaces"]),
            resources=_uj(r["resources"]),
            auth_states=_uj(r["auth_states"]),
            transitions=_uj(r["transitions"]),
        )

    def save_attack_path(self, p: AttackPath) -> None:
        self._conn.execute(
            "INSERT INTO attack_paths "
            "(id, campaign_id, actor_id, interface, resource_id, operation, outcome) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (p.id, p.campaign_id, p.actor_id, p.interface, p.resource_id,
             p.operation, p.outcome.value),
        )
        self._commit()

    def list_attack_paths(
        self,
        actor_ids: list[str] | None = None,
        outcome: TestOutcome | None = None,
        campaign_id: str | None = None,
    ) -> list[AttackPath]:
        """List attack paths, optionally filtered by actor, outcome, campaign."""
        sql = "SELECT * FROM attack_paths"
        clauses: list[str] = []
        params: list = []
        if actor_ids:
            marks = ",".join("?" * len(actor_ids))
            clauses.append(f"actor_id IN ({marks})")
            params.extend(actor_ids)
        if outcome:
            clauses.append("outcome = ?")
            params.append(outcome.value)
        if campaign_id:
            clauses.append("campaign_id = ?")
            params.append(campaign_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        cur = self._conn.execute(sql, params)
        return [
            AttackPath(
                id=r["id"],
                campaign_id=r["campaign_id"],
                actor_id=r["actor_id"],
                interface=r["interface"],
                resource_id=r["resource_id"],
                operation=r["operation"],
                outcome=TestOutcome(r["outcome"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # CRUD — Impact verifications
    # ------------------------------------------------------------------ #

    def save_impact_verification(self, v: ImpactVerification) -> None:
        self._conn.execute(
            "INSERT INTO impact_verifications "
            "(id, finding_id, verifier, verified, method, detail, verified_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (v.id, v.finding_id, v.verifier, 1 if v.verified else 0,
             v.method, _j(v.detail), v.verified_at.isoformat()),
        )
        self._commit()

    def get_impact_verifications(self, finding_id: str) -> list[ImpactVerification]:
        cur = self._conn.execute(
            "SELECT * FROM impact_verifications WHERE finding_id = ? "
            "ORDER BY verified_at DESC",
            (finding_id,),
        )
        return [
            ImpactVerification(
                id=r["id"],
                finding_id=r["finding_id"],
                verifier=r["verifier"],
                verified=bool(r["verified"]),
                method=r["method"],
                detail=_uj(r["detail"]),
                verified_at=_dt(r["verified_at"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # CRUD — Proof sessions
    # ------------------------------------------------------------------ #

    def save_proof_session(self, s: ProofSession) -> None:
        self._conn.execute(
            "INSERT INTO proof_sessions "
            "(id, finding_id, campaign_id, target_id, target_adapter, "
            " actor_id, resource_id, username, key_hash, status, created_at, "
            " expires_at, revoked_at, last_used_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (s.id, s.finding_id, s.campaign_id, s.target_id,
             s.target_adapter, s.actor_id, s.resource_id, s.username,
             s.key_hash, s.status.value, s.created_at.isoformat(),
             s.expires_at.isoformat(),
             s.revoked_at.isoformat() if s.revoked_at else None,
             s.last_used_at.isoformat() if s.last_used_at else None),
        )
        self._commit()

    def get_proof_session(self, session_id: str) -> ProofSession | None:
        cur = self._conn.execute(
            "SELECT * FROM proof_sessions WHERE id = ?", (session_id,)
        )
        r = cur.fetchone()
        if r is None:
            return None
        return self._row_to_proof_session(r)

    def _row_to_proof_session(self, r: sqlite3.Row) -> ProofSession:
        return ProofSession(
            id=r["id"],
            finding_id=r["finding_id"],
            campaign_id=r["campaign_id"],
            target_id=r["target_id"],
            target_adapter=r["target_adapter"],
            actor_id=r["actor_id"],
            resource_id=r["resource_id"],
            username=r["username"],
            key_hash=r["key_hash"],
            status=ProofSessionStatus(r["status"]),
            created_at=_dt(r["created_at"]),
            expires_at=_dt(r["expires_at"]),
            revoked_at=_opt_dt(r["revoked_at"]),
            last_used_at=_opt_dt(r["last_used_at"]),
        )

    def list_proof_sessions(self) -> list[ProofSession]:
        cur = self._conn.execute(
            "SELECT * FROM proof_sessions ORDER BY created_at DESC"
        )
        return [self._row_to_proof_session(r) for r in cur.fetchall()]

    def update_proof_session_status(
        self, session_id: str, status: ProofSessionStatus
    ) -> None:
        self._conn.execute(
            "UPDATE proof_sessions SET status = ? WHERE id = ?",
            (status.value, session_id),
        )
        self._commit()

    def revoke_proof_session(
        self, session_id: str, revoked_at: datetime.datetime
    ) -> None:
        """Revoke a proof session, persisting both status and revoked_at.

        The historical record is preserved; only status and revoked_at are
        modified.
        """
        self._conn.execute(
            "UPDATE proof_sessions SET status = ?, revoked_at = ? WHERE id = ?",
            (ProofSessionStatus.REVOKED.value, revoked_at.isoformat(), session_id),
        )
        self._commit()

    def touch_proof_session(self, session_id: str) -> None:
        self._conn.execute(
            "UPDATE proof_sessions SET last_used_at = ? WHERE id = ?",
            (_now(), session_id),
        )
        self._commit()

    # ------------------------------------------------------------------ #
    # CRUD — Case studies
    # ------------------------------------------------------------------ #

    def save_case_study(self, cs: CaseStudy) -> None:
        self._conn.execute(
            "INSERT INTO case_studies "
            "(id, finding_id, title, body, created_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (cs.id, cs.finding_id, cs.title, _j(cs.body), cs.created_at.isoformat()),
        )
        self._commit()

    def get_case_study(self, case_study_id: str) -> CaseStudy | None:
        cur = self._conn.execute(
            "SELECT * FROM case_studies WHERE id = ?", (case_study_id,)
        )
        r = cur.fetchone()
        if r is None:
            return None
        return CaseStudy(
            id=r["id"],
            finding_id=r["finding_id"],
            title=r["title"],
            body=_uj(r["body"]),
            created_at=_dt(r["created_at"]),
        )

    def list_case_studies(self) -> list[CaseStudy]:
        cur = self._conn.execute("SELECT * FROM case_studies ORDER BY created_at")
        return [
            CaseStudy(
                id=r["id"],
                finding_id=r["finding_id"],
                title=r["title"],
                body=_uj(r["body"]),
                created_at=_dt(r["created_at"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # Analytical queries
    # ------------------------------------------------------------------ #

    def previous_attempts(self, target_id: str) -> list[Experiment]:
        """Return all experiments for a target, newest first."""
        cur = self._conn.execute(
            "SELECT * FROM experiments WHERE target_id = ? "
            "ORDER BY started_at DESC",
            (target_id,),
        )
        return [self._row_to_experiment(r) for r in cur.fetchall()]

    def what_failed(self, target_id: str) -> list[Experiment]:
        """Return experiments that failed (attacks blocked by a defense)."""
        cur = self._conn.execute(
            "SELECT * FROM experiments WHERE target_id = ? "
            "AND outcome = ? ORDER BY started_at DESC",
            (target_id, TestOutcome.FAILURE.value),
        )
        return [self._row_to_experiment(r) for r in cur.fetchall()]

    def open_findings(self) -> list[Finding]:
        """Return findings not yet closed."""
        cur = self._conn.execute(
            "SELECT * FROM findings WHERE verification_status != ? "
            "ORDER BY created_at DESC",
            (FindingStatus.CLOSED.value,),
        )
        return [self._row_to_finding(r) for r in cur.fetchall()]

    def build_report(self, target_id: str) -> ResearchReport:
        """Build a summary report for a target.

        The report covers both research models: v0.1 hypothesis experiments
        and v0.2+ campaign boundary tests. Campaign paths are reported as
        boundary tests, never masquerading as experiments.
        """
        exps = self.list_experiments(target_id)
        hyps = self.list_hypotheses(target_id)
        finds = self.list_findings(target_id)
        successes = sum(1 for e in exps if e.outcome == TestOutcome.SUCCESS)
        failures = sum(1 for e in exps if e.outcome == TestOutcome.FAILURE)
        blocked = sum(1 for e in exps if e.outcome == TestOutcome.BLOCKED)
        inconclusive = sum(1 for e in exps if e.outcome == TestOutcome.INCONCLUSIVE)

        attack_classes = set()
        for e in exps:
            cls = e.test.parameters.get("weakness", "unknown")
            attack_classes.add(cls)

        open_finds = sum(
            1 for f in finds if f.verification_status != FindingStatus.CLOSED
        )

        campaign_paths_tested = 0
        campaign_violations = 0
        for campaign in self.list_campaigns():
            if campaign.target_id != target_id:
                continue
            paths = self.list_attack_paths(campaign_id=campaign.id)
            campaign_paths_tested += len(paths)
            campaign_violations += sum(
                1 for p in paths if p.outcome == TestOutcome.SUCCESS
            )

        return ResearchReport(
            target_id=target_id,
            opensystem_version=VERSION,
            rounds_executed=len(exps),
            hypotheses_formed=len(hyps),
            experiments_run=len(exps),
            successful_tests=successes,
            failed_tests=failures,
            blocked_tests=blocked,
            inconclusive_tests=inconclusive,
            findings_created=len(finds),
            open_findings=open_finds,
            attack_classes_attempted=attack_classes,
            campaign_paths_tested=campaign_paths_tested,
            campaign_violations=campaign_violations,
        )
