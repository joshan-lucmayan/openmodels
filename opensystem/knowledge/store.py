"""Persistent knowledge store (Phase 10).

OpenSystem uses SQLite as its persistent store. This decision was made
because:

- SQLite is zero-configuration and built into Python's standard library.
- For single-instance, single-user deployments — the expected usage pattern —
  SQLite is more than sufficient.
- It avoids external database-server dependencies.
- The schema is defined as pydantic model serialization, so migration to
  PostgreSQL or another backend is a matter of swapping the store
  implementation behind the same interface.

The store records everything: observations, hypotheses, experiments, evidence,
findings, knowledge, and evolution events. A future attacker can ask questions
like "What did we previously try?", "What failed?", "What changed since then?".

Write semantics
---------------
Two intentional write policies exist (see ADR 005 for the integrity model):

- **Append-only** (audit/history records): ``INSERT ... ON CONFLICT(id) DO
  NOTHING``. The first version of a record wins; a repeated save can never
  silently overwrite history.
- **Upsert** (mutable state such as findings status, targets): ``INSERT OR
  REPLACE`` with a stable id. Re-saving a mutated model is an intentional
  update.

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
    Evidence,
    EvidenceKind,
    EvolutionEvent,
    EvolutionTrigger,
    Experiment,
    Finding,
    FindingStatus,
    Hypothesis,
    HypothesisStatus,
    JournalEntry,
    Knowledge,
    KnowledgeKind,
    Observation,
    ResearchReport,
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


def _migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
    """v0.2 → v0.3: no-op.

    The v0.2-era tables (impact verifications, proof sessions, case studies)
    were removed in v0.4 and are no longer created. This step exists only to
    keep the migration chain continuous for legacy databases.
    """


def _migrate_v2_to_v3(conn: sqlite3.Connection) -> None:
    """v0.3 → v0.3.1: structured finding identities + environment/scope.

    Additive only. Targets gain declared environment/scope columns (left
    empty for legacy rows — undeclared scopes fail closed in policy
    matching).
    """
    finding_cols = _table_columns(conn, "findings")
    for column in ("objective_id", "actor_id", "resource_id", "interface"):
        if column not in finding_cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT")

    target_cols = _table_columns(conn, "targets")
    for column in ("environment", "scope"):
        if column not in target_cols:
            conn.execute(
                f"ALTER TABLE targets ADD COLUMN {column} TEXT DEFAULT ''"
            )


def _migrate_v3_to_v4(conn: sqlite3.Connection) -> None:
    """v0.3.1 → v0.4: drop mock-boundary-era tables.

    The campaign/proof/impact/defense subsystems were removed when the mock
    target was deleted. Their tables are dropped; the surviving research
    tables are untouched.
    """
    dropped = (
        "defenses", "regressions", "protected_resources", "actors",
        "entitlements", "security_invariants", "attack_objectives",
        "campaigns", "attack_surfaces", "attack_paths",
        "impact_verifications", "proof_sessions", "case_studies",
    )
    for table in dropped:
        conn.execute(f"DROP TABLE IF EXISTS {table}")


def _migrate_v4_to_v5(conn: sqlite3.Connection) -> None:
    """v0.4 → v0.4.1: attack journal table."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS journal_entries (
            id             TEXT PRIMARY KEY,
            target_id      TEXT NOT NULL,
            target_url     TEXT DEFAULT '',
            attack_key     TEXT DEFAULT '',
            attack_name    TEXT DEFAULT '',
            family         TEXT DEFAULT '',
            outcome        TEXT NOT NULL DEFAULT 'INCONCLUSIVE',
            summary        TEXT DEFAULT '',
            how_it_was_done TEXT DEFAULT '',
            observed_result TEXT DEFAULT '',
            detail         TEXT DEFAULT '{}',
            evidence_ids   TEXT DEFAULT '[]',
            hypothesis_id  TEXT,
            experiment_id  TEXT,
            created_at     TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_journal_target ON "
        "journal_entries(target_id)"
    )


MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    2: _migrate_v1_to_v2,
    3: _migrate_v2_to_v3,
    4: _migrate_v3_to_v4,
    5: _migrate_v4_to_v5,
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
    # Metadata
    # ------------------------------------------------------------------ #

    def get_metadata(self, key: str) -> str | None:
        cur = self._conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        )
        row = cur.fetchone()
        return row["value"] if row else None

    def set_metadata(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._commit()

    def delete_metadata(self, key: str) -> None:
        self._conn.execute("DELETE FROM metadata WHERE key = ?", (key,))
        self._commit()

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

        CREATE TABLE IF NOT EXISTS journal_entries (
            id             TEXT PRIMARY KEY,
            target_id      TEXT NOT NULL,
            target_url     TEXT DEFAULT '',
            attack_key     TEXT DEFAULT '',
            attack_name    TEXT DEFAULT '',
            family         TEXT DEFAULT '',
            outcome        TEXT NOT NULL DEFAULT 'INCONCLUSIVE',
            summary        TEXT DEFAULT '',
            how_it_was_done TEXT DEFAULT '',
            observed_result TEXT DEFAULT '',
            detail         TEXT DEFAULT '{}',
            evidence_ids   TEXT DEFAULT '[]',
            hypothesis_id  TEXT,
            experiment_id  TEXT,
            created_at     TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_hypotheses_target ON hypotheses(target_id);
        CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(status);
        CREATE INDEX IF NOT EXISTS idx_experiments_hypothesis ON experiments(hypothesis_id);
        CREATE INDEX IF NOT EXISTS idx_experiments_target ON experiments(target_id);
        CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(verification_status);
        CREATE INDEX IF NOT EXISTS idx_knowledge_target ON knowledge(target_id);
        CREATE INDEX IF NOT EXISTS idx_knowledge_kind ON knowledge(kind);
        CREATE INDEX IF NOT EXISTS idx_journal_target ON journal_entries(target_id);
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
               (id, target_id, hypothesis_id, severity, affected_component,
                attack_hypothesis, observed_behavior, evidence_ids, impact,
                reproduction, recommended_mitigation, verification_status,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f.id, f.target_id, f.hypothesis_id, f.severity.value,
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

    def update_finding_status(self, finding_id: str, status: FindingStatus) -> None:
        self._conn.execute(
            "UPDATE findings SET verification_status = ?, updated_at = ? WHERE id = ?",
            (status.value, _now(), finding_id),
        )
        self._commit()

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
    # CRUD — Journal
    # ------------------------------------------------------------------ #

    def save_journal_entry(self, entry: JournalEntry) -> None:
        self._conn.execute(
            "INSERT INTO journal_entries "
            "(id, target_id, target_url, attack_key, attack_name, family, "
            " outcome, summary, how_it_was_done, observed_result, detail, "
            " evidence_ids, hypothesis_id, experiment_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (
                entry.id, entry.target_id, entry.target_url, entry.attack_key,
                entry.attack_name, entry.family, entry.outcome.value,
                entry.summary, entry.how_it_was_done, entry.observed_result,
                _j(entry.detail), _j(entry.evidence_ids),
                entry.hypothesis_id, entry.experiment_id,
                entry.created_at.isoformat(),
            ),
        )
        self._commit()

    def _row_to_journal_entry(self, r: sqlite3.Row) -> JournalEntry:
        detail = r["detail"]
        if detail and not detail.startswith("{"):
            # An encrypted detail payload is a raw string, not JSON.
            detail_value: Any = detail
        else:
            detail_value = _uj(detail)
        return JournalEntry(
            id=r["id"],
            target_id=r["target_id"],
            target_url=r["target_url"],
            attack_key=r["attack_key"],
            attack_name=r["attack_name"],
            family=r["family"],
            outcome=TestOutcome(r["outcome"]),
            summary=r["summary"],
            how_it_was_done=r["how_it_was_done"],
            observed_result=r["observed_result"],
            detail=detail_value,
            evidence_ids=_uj(r["evidence_ids"]),
            hypothesis_id=r["hypothesis_id"],
            experiment_id=r["experiment_id"],
            created_at=_dt(r["created_at"]),
        )

    def get_journal_entry(self, entry_id: str) -> JournalEntry | None:
        cur = self._conn.execute(
            "SELECT * FROM journal_entries WHERE id = ?", (entry_id,)
        )
        r = cur.fetchone()
        return self._row_to_journal_entry(r) if r else None

    def list_journal_entries(
        self, target_id: str | None = None, attack_key: str | None = None
    ) -> list[JournalEntry]:
        sql = "SELECT * FROM journal_entries"
        clauses: list[str] = []
        params: list = []
        if target_id:
            clauses.append("target_id = ?")
            params.append(target_id)
        if attack_key:
            clauses.append("attack_key = ?")
            params.append(attack_key)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at"
        cur = self._conn.execute(sql, params)
        return [self._row_to_journal_entry(r) for r in cur.fetchall()]

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
        """Build a summary report for a target."""
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
        )
