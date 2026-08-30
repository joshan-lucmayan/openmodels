"""Tests for the schema migration system, including a representative v0.2
database upgraded in place without data loss."""

from __future__ import annotations

import sqlite3

import pytest

from opensystem.knowledge.store import KnowledgeStore
from opensystem.version import SCHEMA_VERSION

# The v0.2 (schema version 1) shape of the tables the v0.3.1 migrations
# touch. Deliberately the OLD shape: no structured finding columns, no
# campaign_id on attack_paths, no environment/scope on targets, and no
# proof-session tables.
V02_SCHEMA = """
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE targets (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
    adapter TEXT NOT NULL, description TEXT DEFAULT '',
    version TEXT DEFAULT '0.0.0', assets TEXT DEFAULT '[]',
    interfaces TEXT DEFAULT '[]', trust_boundaries TEXT DEFAULT '[]',
    rules TEXT DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

CREATE TABLE hypotheses (
    id TEXT PRIMARY KEY, target_id TEXT NOT NULL, statement TEXT NOT NULL,
    assumption TEXT DEFAULT '', status TEXT NOT NULL, parent_id TEXT,
    origin TEXT DEFAULT 'manual', confidence REAL DEFAULT 0.5,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY, target_id TEXT NOT NULL, hypothesis_id TEXT,
    severity TEXT NOT NULL DEFAULT 'MEDIUM', affected_component TEXT DEFAULT '',
    attack_hypothesis TEXT DEFAULT '', observed_behavior TEXT DEFAULT '',
    evidence_ids TEXT DEFAULT '[]', impact TEXT DEFAULT '',
    reproduction TEXT DEFAULT '', recommended_mitigation TEXT DEFAULT '',
    verification_status TEXT NOT NULL DEFAULT 'DISCOVERED',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

CREATE TABLE experiments (
    id TEXT PRIMARY KEY, hypothesis_id TEXT NOT NULL, target_id TEXT NOT NULL,
    opensystem_version TEXT NOT NULL, test_name TEXT DEFAULT '',
    test_description TEXT DEFAULT '', test_parameters TEXT DEFAULT '{}',
    expected_outcome TEXT DEFAULT 'SUCCESS', expected_result TEXT DEFAULT '',
    observed_result TEXT DEFAULT '', outcome TEXT NOT NULL,
    conclusion TEXT DEFAULT '', next_hypothesis_id TEXT,
    evidence_ids TEXT DEFAULT '[]', started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE attack_paths (
    id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, interface TEXT NOT NULL,
    resource_id TEXT NOT NULL, operation TEXT DEFAULT 'access',
    outcome TEXT NOT NULL DEFAULT 'INCONCLUSIVE'
);

CREATE TABLE actors (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
    description TEXT DEFAULT '', entitlements TEXT DEFAULT '[]'
);

CREATE TABLE protected_resources (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, resource_type TEXT NOT NULL,
    value TEXT DEFAULT '', description TEXT DEFAULT '', interfaces TEXT DEFAULT '[]'
);
"""

LEGACY_COMPONENT = (
    "actor=UNAUTHENTICATED/free_user → interface=[stream_api] → "
    "resource=premium_model"
)


@pytest.fixture()
def v02_db_path(tmp_path):
    """A representative v0.2 database with legacy rows."""
    path = str(tmp_path / "v02.db")
    conn = sqlite3.connect(path)
    conn.executescript(V02_SCHEMA)
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('schema_version', '1')"
    )
    conn.execute(
        "INSERT INTO targets (id, name, kind, adapter, created_at, updated_at) "
        "VALUES ('target_m', 'mock-service', 'mock', 'mock', "
        "'2026-08-29T00:00:00+00:00', '2026-08-29T00:00:00+00:00')"
    )
    conn.execute(
        "INSERT INTO hypotheses (id, target_id, statement, status, created_at, "
        "updated_at) VALUES ('h1', 'target_m', 'legacy hypothesis', "
        "'ACCEPTED', '2026-08-29T00:00:00+00:00', '2026-08-29T00:00:00+00:00')"
    )
    conn.execute(
        "INSERT INTO actors (id, name, kind, description, entitlements) "
        "VALUES ('actor_free_user', 'free_user', 'FREE_USER', '', '[]')"
    )
    conn.execute(
        "INSERT INTO protected_resources (id, name, resource_type, value, "
        "description, interfaces) VALUES ('res_premium_model', "
        "'premium_model', 'ai_model', 'premium AI inference', '', '[]')"
    )
    # A well-formed legacy campaign finding: backfillable.
    conn.execute(
        "INSERT INTO findings (id, target_id, hypothesis_id, severity, "
        "affected_component, verification_status, created_at, updated_at) "
        "VALUES ('f1', 'target_m', 'h1', 'HIGH', ?, 'DISCOVERED', "
        "'2026-08-29T00:00:00+00:00', '2026-08-29T00:00:00+00:00')",
        (LEGACY_COMPONENT,),
    )
    # A malformed legacy finding: must NOT be guessed at.
    conn.execute(
        "INSERT INTO findings (id, target_id, severity, affected_component, "
        "verification_status, created_at, updated_at) "
        "VALUES ('f2', 'target_m', 'MEDIUM', 'auth-bypass', 'DISCOVERED', "
        "'2026-08-29T00:00:00+00:00', '2026-08-29T00:00:00+00:00')"
    )
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()
    return path


def test_v02_database_migrates_in_place(v02_db_path):
    store = KnowledgeStore(v02_db_path)
    try:
        (version,) = store._conn.execute("PRAGMA user_version").fetchone()
        assert version == SCHEMA_VERSION

        # v0.3 tables created by migration 2.
        tables = {
            r["name"] for r in store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {"impact_verifications", "proof_sessions", "case_studies"} <= tables

        # Structured columns added by migration 3.
        finding_cols = {
            r["name"] for r in store._conn.execute("PRAGMA table_info(findings)")
        }
        assert {"objective_id", "actor_id", "resource_id", "interface"} <= finding_cols
        path_cols = {
            r["name"] for r in store._conn.execute("PRAGMA table_info(attack_paths)")
        }
        assert "campaign_id" in path_cols
        target_cols = {
            r["name"] for r in store._conn.execute("PRAGMA table_info(targets)")
        }
        assert {"environment", "scope"} <= target_cols
    finally:
        store.close()


def test_v02_legacy_finding_backfilled(v02_db_path):
    store = KnowledgeStore(v02_db_path)
    try:
        finding = store.get_finding("f1")
        assert finding.actor_id == "actor_free_user"
        assert finding.resource_id == "res_premium_model"
        assert finding.interface == "stream_api"
        # The original display data is preserved untouched.
        assert finding.affected_component == LEGACY_COMPONENT
    finally:
        store.close()


def test_v02_malformed_finding_left_unresolved(v02_db_path):
    store = KnowledgeStore(v02_db_path)
    try:
        finding = store.get_finding("f2")
        assert finding.actor_id is None
        assert finding.resource_id is None
        assert finding.interface is None
        assert finding.affected_component == "auth-bypass"
    finally:
        store.close()


def test_v02_data_survives_migration(v02_db_path):
    store = KnowledgeStore(v02_db_path)
    try:
        assert store.get_target("target_m").name == "mock-service"
        hyps = store.list_hypotheses("target_m")
        assert len(hyps) == 1
        assert hyps[0].statement == "legacy hypothesis"

        # The migrated store is fully usable for new writes.
        from opensystem.models import Finding

        finding = Finding(target_id="target_m", interface="chat_api")
        store.save_finding(finding)
        assert store.get_finding(finding.id).interface == "chat_api"
    finally:
        store.close()


def test_current_database_is_not_re_migrated(tmp_path):
    """A database already at the current version is left untouched."""
    path = str(tmp_path / "current.db")
    store = KnowledgeStore(path)
    store.close()

    store = KnowledgeStore(path)
    try:
        (version,) = store._conn.execute("PRAGMA user_version").fetchone()
        assert version == SCHEMA_VERSION
    finally:
        store.close()
