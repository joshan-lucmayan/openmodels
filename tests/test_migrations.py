"""Tests for the schema migration system.

These verify that a legacy (v0.2-era, schema version 1) database is upgraded
in place to the current schema without data loss, and that the mock-boundary
tables are dropped.
"""

from __future__ import annotations

import sqlite3

import pytest

from opensystem.knowledge.store import KnowledgeStore
from opensystem.version import SCHEMA_VERSION

# The v0.2 (schema version 1) shape of the tables the migrations touch.
LEGACY_SCHEMA = """
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

CREATE TABLE campaigns (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, target_id TEXT NOT NULL,
    target_adapter TEXT DEFAULT '', description TEXT DEFAULT '',
    actor_ids TEXT DEFAULT '[]', resource_ids TEXT DEFAULT '[]',
    objective_ids TEXT DEFAULT '[]', invariant_ids TEXT DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'CREATED', created_at TEXT NOT NULL,
    started_at TEXT, completed_at TEXT
);

CREATE TABLE proof_sessions (
    id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, campaign_id TEXT DEFAULT '',
    target_id TEXT NOT NULL, target_adapter TEXT DEFAULT '',
    actor_id TEXT NOT NULL, resource_id TEXT NOT NULL, username TEXT DEFAULT '',
    key_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    revoked_at TEXT, last_used_at TEXT
);
"""


@pytest.fixture()
def legacy_db_path(tmp_path):
    """A representative legacy database with research and boundary rows."""
    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_SCHEMA)
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('schema_version', '1')"
    )
    conn.execute(
        "INSERT INTO targets (id, name, kind, adapter, created_at, updated_at) "
        "VALUES ('target_www', 'www.example.com', 'web', 'http', "
        "'2026-08-29T00:00:00+00:00', '2026-08-29T00:00:00+00:00')"
    )
    conn.execute(
        "INSERT INTO hypotheses (id, target_id, statement, status, created_at, "
        "updated_at) VALUES ('h1', 'target_www', 'legacy hypothesis', "
        "'ACCEPTED', '2026-08-29T00:00:00+00:00', '2026-08-29T00:00:00+00:00')"
    )
    conn.execute(
        "INSERT INTO findings (id, target_id, severity, affected_component, "
        "verification_status, created_at, updated_at) "
        "VALUES ('f1', 'target_www', 'HIGH', 'http-sensitive-paths', "
        "'DISCOVERED', '2026-08-29T00:00:00+00:00', "
        "'2026-08-29T00:00:00+00:00')"
    )
    conn.execute(
        "INSERT INTO campaigns (id, name, target_id, created_at) "
        "VALUES ('c1', 'legacy campaign', 'target_www', "
        "'2026-08-29T00:00:00+00:00')"
    )
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()
    return path


def test_legacy_database_migrates_in_place(legacy_db_path):
    store = KnowledgeStore(legacy_db_path)
    try:
        (version,) = store._conn.execute("PRAGMA user_version").fetchone()
        assert version == SCHEMA_VERSION

        # Research tables survive.
        assert store.get_target("target_www").name == "www.example.com"
        hyps = store.list_hypotheses("target_www")
        assert len(hyps) == 1
        assert hyps[0].statement == "legacy hypothesis"
        finding = store.get_finding("f1")
        assert finding.affected_component == "http-sensitive-paths"
    finally:
        store.close()


def test_mock_boundary_tables_are_dropped(legacy_db_path):
    store = KnowledgeStore(legacy_db_path)
    try:
        tables = {
            r["name"] for r in store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        for removed in (
            "campaigns", "proof_sessions", "impact_verifications",
            "case_studies", "defenses", "regressions", "actors",
            "protected_resources", "attack_paths",
        ):
            assert removed not in tables
    finally:
        store.close()


def test_environment_and_scope_columns_added(legacy_db_path):
    store = KnowledgeStore(legacy_db_path)
    try:
        target_cols = {
            r["name"] for r in store._conn.execute("PRAGMA table_info(targets)")
        }
        assert {"environment", "scope"} <= target_cols
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