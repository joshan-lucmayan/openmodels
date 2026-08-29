"""Persistent knowledge store (Phase 10).

OpenModels uses SQLite as its initial persistent store. This decision was
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
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from openmodels import VERSION
from openmodels.models import (
    Defense,
    Evidence,
    EvolutionEvent,
    EvolutionTrigger,
    Experiment,
    Finding,
    FindingStatus,
    Hypothesis,
    HypothesisStatus,
    Knowledge,
    KnowledgeKind,
    Observation,
    Regression,
    ResearchReport,
    Severity,
    Target,
    TestOutcome,
    TestSpec,
)
from openmodels.version import SCHEMA_VERSION


def _j(data: Any) -> str:
    """Serialize a dict/list to JSON for storage."""
    return json.dumps(data, default=str)


def _uj(raw: str | None) -> Any:
    """Deserialize JSON; return empty dict on None or empty."""
    if not raw:
        return {}
    return json.loads(raw)


class KnowledgeStore:
    """SQLite-backed persistent store for the OpenModels research graph.

    Every public method accepts model instances and returns lists of model
    instances. The SQLite details are an implementation concern.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._conn: sqlite3.Connection | None = None
        self._ensure_schema()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #

    def _ensure_schema(self) -> None:
        first = not os.path.exists(self._path)
        self._conn = sqlite3.connect(self._path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row

        if first:
            self._create_tables()

    def _create_tables(self) -> None:
        cur = self._conn.execute("PRAGMA user_version")
        (v,) = cur.fetchone()
        if v >= SCHEMA_VERSION:
            return

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
            openmodels_version TEXT NOT NULL,
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

        CREATE INDEX IF NOT EXISTS idx_hypotheses_target ON hypotheses(target_id);
        CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(status);
        CREATE INDEX IF NOT EXISTS idx_experiments_hypothesis ON experiments(hypothesis_id);
        CREATE INDEX IF NOT EXISTS idx_experiments_target ON experiments(target_id);
        CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(verification_status);
        CREATE INDEX IF NOT EXISTS idx_knowledge_target ON knowledge(target_id);
        CREATE INDEX IF NOT EXISTS idx_knowledge_kind ON knowledge(kind);
        """
        self._conn.executescript(sql)
        self._conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("openmodels_version", VERSION),
        )
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
            created_at=datetime.datetime.fromisoformat(r["created_at"]),
            updated_at=datetime.datetime.fromisoformat(r["updated_at"]),
        )

    def _target_to_row(self, t: Target) -> dict:
        return dict(
            id=t.id,
            name=t.name,
            kind=t.kind,
            adapter=t.adapter,
            description=t.description,
            version=t.version,
            assets=_j(t.assets),
            interfaces=_j(t.interfaces),
            trust_boundaries=_j(t.trust_boundaries),
            rules=_j(t.rules),
            created_at=t.created_at.isoformat(),
            updated_at=t.updated_at.isoformat(),
        )

    # ------------------------------------------------------------------ #
    # CRUD — Targets
    # ------------------------------------------------------------------ #

    def save_target(self, target: Target) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO targets
               (id, name, kind, adapter, description, version, assets,
                interfaces, trust_boundaries, rules, created_at, updated_at)
               VALUES (:id, :name, :kind, :adapter, :description, :version,
                :assets, :interfaces, :trust_boundaries, :rules,
                :created_at, :updated_at)""",
            self._target_to_row(target),
        )
        self._conn.commit()

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
            "INSERT OR REPLACE INTO observations "
            "(id, target_id, interface, data, source, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (obs.id, obs.target_id, obs.interface, _j(obs.data),
             obs.source, obs.timestamp.isoformat()),
        )
        self._conn.commit()

    def save_observations(self, obs_list: list[Observation]) -> None:
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
                timestamp=datetime.datetime.fromisoformat(r["timestamp"]),
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
        self._conn.commit()

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
            created_at=datetime.datetime.fromisoformat(r["created_at"]),
            updated_at=datetime.datetime.fromisoformat(r["updated_at"]),
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
            (status.value, datetime.datetime.now(datetime.timezone.utc).isoformat(), hypothesis_id),
        )
        self._conn.commit()

    # ------------------------------------------------------------------ #
    # CRUD — Experiments
    # ------------------------------------------------------------------ #

    def save_experiment(self, e: Experiment) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO experiments
               (id, hypothesis_id, target_id, openmodels_version,
                test_name, test_description, test_parameters,
                expected_outcome, expected_result, observed_result,
                outcome, conclusion, next_hypothesis_id, evidence_ids,
                started_at, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                e.id, e.hypothesis_id, e.target_id, e.openmodels_version,
                e.test.name, e.test.description, _j(e.test.parameters),
                e.test.expected_outcome.value, e.expected_result,
                e.observed_result, e.outcome.value, e.conclusion,
                e.next_hypothesis_id, _j(e.evidence_ids),
                e.started_at.isoformat(),
                e.completed_at.isoformat() if e.completed_at else None,
            ),
        )
        self._conn.commit()

    def _row_to_experiment(self, r: sqlite3.Row) -> Experiment:
        return Experiment(
            id=r["id"],
            hypothesis_id=r["hypothesis_id"],
            target_id=r["target_id"],
            openmodels_version=r["openmodels_version"],
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
            started_at=datetime.datetime.fromisoformat(r["started_at"]),
            completed_at=(
                datetime.datetime.fromisoformat(r["completed_at"])
                if r["completed_at"] else None
            ),
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
            "INSERT OR REPLACE INTO evidence "
            "(id, experiment_id, kind, data, reference, captured_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (e.id, e.experiment_id, e.kind.value, _j(e.data),
             e.reference, e.captured_at.isoformat()),
        )
        self._conn.commit()

    def save_evidence_list(self, ev_list: list[Evidence]) -> None:
        for e in ev_list:
            self.save_evidence(e)

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
        self._conn.commit()

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
            created_at=datetime.datetime.fromisoformat(r["created_at"]),
            updated_at=datetime.datetime.fromisoformat(r["updated_at"]),
        )

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
            (status.value, datetime.datetime.now(datetime.timezone.utc).isoformat(), finding_id),
        )
        self._conn.commit()

    # ------------------------------------------------------------------ #
    # CRUD — Defenses
    # ------------------------------------------------------------------ #

    def save_defense(self, d: Defense) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO defenses "
            "(id, finding_id, description, verification_status, applied_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (d.id, d.finding_id, d.description, d.verification_status.value,
             d.applied_at.isoformat()),
        )
        self._conn.commit()

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
                applied_at=datetime.datetime.fromisoformat(r["applied_at"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # CRUD — Regressions
    # ------------------------------------------------------------------ #

    def save_regression(self, r: Regression) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO regressions "
            "(id, defense_id, hypothesis_id, target_id, outcome, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (r.id, r.defense_id, r.hypothesis_id, r.target_id,
             r.outcome.value, r.detail, r.created_at.isoformat()),
        )
        self._conn.commit()

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
                created_at=datetime.datetime.fromisoformat(r["created_at"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # CRUD — Knowledge
    # ------------------------------------------------------------------ #

    def save_knowledge(self, k: Knowledge) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO knowledge "
            "(id, kind, content, target_id, provenance, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (k.id, k.kind.value, k.content, k.target_id,
             k.provenance, k.created_at.isoformat()),
        )
        self._conn.commit()

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
                created_at=datetime.datetime.fromisoformat(r["created_at"]),
            )
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------ #
    # CRUD — Evolution Events
    # ------------------------------------------------------------------ #

    def save_evolution_event(self, ev: EvolutionEvent) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO evolution_events "
            "(id, trigger, reason, from_hypothesis_id, to_hypothesis_id, "
            " provenance, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ev.id, ev.trigger.value, ev.reason, ev.from_hypothesis_id,
             ev.to_hypothesis_id, ev.provenance, ev.created_at.isoformat()),
        )
        self._conn.commit()

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
                created_at=datetime.datetime.fromisoformat(r["created_at"]),
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
            openmodels_version=VERSION,
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