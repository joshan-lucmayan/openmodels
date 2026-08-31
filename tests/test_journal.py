"""Tests for the attack journal system."""

from __future__ import annotations

import pytest

from opensystem.journal.engine import JournalEngine
from opensystem.journal.playbook import ATTACK_KEYS, PLAYBOOK, playbook_for
from opensystem.models import (
    Experiment,
    Hypothesis,
    Target,
    TestOutcome,
    TestSpec,
)


def _experiment(store, outcome=TestOutcome.SUCCESS, origin="strategy:http-tls"):
    hyp = Hypothesis(
        target_id="t1",
        statement="can http-tls be demonstrated as a weakness?",
        origin=origin,
    )
    store.save_hypothesis(hyp)
    exp = Experiment(
        hypothesis_id=hyp.id,
        target_id="t1",
        opensystem_version="0.4.1",
        test=TestSpec(
            name="test-http-tls",
            parameters={"weakness": "http-tls"},
        ),
        observed_result="Target served over plaintext HTTP.",
        outcome=outcome,
    )
    return hyp, exp


def test_playbook_covers_every_http_attack():
    """Every planner attack key must have documented methodology."""
    from opensystem.attack.planner import HTTP_STRATEGIES

    strategy_keys = {s.weakness_key for s in HTTP_STRATEGIES}
    assert strategy_keys == set(ATTACK_KEYS)
    for key in ATTACK_KEYS:
        p = playbook_for(key)
        assert p is not None, f"missing playbook entry: {key}"
        assert p["how_it_was_done"]
        assert p["why_it_matters"]


def test_playbook_all_entries_have_full_details():
    for p in PLAYBOOK.values():
        assert p["name"]
        assert p["family"]
        assert p["summary"]
        assert p["how_it_was_done"]
        assert p["why_it_matters"]


def test_record_experiment_persists(store):
    from opensystem.models import Target

    engine = JournalEngine(store)
    hyp, exp = _experiment(store)
    entry = engine.record_experiment(
        Target(id="t1", name="www.example.com",
               rules={"base_url": "https://www.example.com"}),
        hyp, exp, detail={"weakness": "http-tls"},
    )
    assert entry.id
    assert entry.attack_key == "http-tls"
    assert entry.attack_name == "Weak Transport Security"
    assert entry.outcome == TestOutcome.SUCCESS
    assert "Methodology" in entry.how_it_was_done
    assert "plaintext HTTP" in entry.how_it_was_done
    assert entry.hypothesis_id == hyp.id
    assert entry.experiment_id == exp.id

    persisted = store.get_journal_entry(entry.id)
    assert persisted is not None
    assert persisted.attack_key == "http-tls"


def test_record_experiment_unknown_attack_still_records(store):
    from opensystem.models import Target

    engine = JournalEngine(store)
    hyp, exp = _experiment(store, origin="strategy:http-unknown")
    entry = engine.record_experiment(Target(id="t1", name="x"), hyp, exp)
    assert entry.attack_key == "http-unknown"
    assert entry.attack_name == "http-unknown"
    assert "Methodology" not in entry.how_it_was_done


def test_journal_filters_by_target_and_attack(store):
    from opensystem.models import Target

    engine = JournalEngine(store)
    hyp1, exp1 = _experiment(store)
    hyp2, exp2 = _experiment(store, origin="strategy:http-cors")
    engine.record_experiment(Target(id="t1", name="a"), hyp1, exp1)
    engine.record_experiment(Target(id="t2", name="b"), hyp2, exp2)

    assert len(engine.list()) == 2
    assert len(engine.list(target_id="t1")) == 1
    assert len(engine.list(attack_key="http-cors")) == 1


def test_export_markdown_includes_entries(store):
    engine = JournalEngine(store)
    hyp, exp = _experiment(store)
    engine.record_experiment(
        Target(id="t1", name="x", rules={"base_url": "https://www.example.com"}),
        hyp, exp,
    )
    md = engine.export_markdown()
    assert "# OpenSystem Attack Journal" in md
    assert "Weak Transport Security" in md
    assert "http-tls" in md
    assert "Methodology" in md
    assert "https://www.example.com" in md


def test_playbook_markdown(store):
    engine = JournalEngine(store)
    md = engine.playbook_markdown()
    assert "# OpenSystem Attack Playbook" in md
    for key in ATTACK_KEYS:
        assert f"`{key}`" in md

    single = engine.playbook_markdown("http-cors")
    assert "CORS Misconfiguration" in single
    assert "http-security-headers" not in single


def test_engine_research_populates_journal(store, http_target):
    from opensystem.attack.planner import default_planner
    from opensystem.core.engine import AdversarialEngine
    from opensystem.policy.models import Policy

    target_model = http_target.discover()
    policy = Policy(
        target_name=target_model.adapter,
        environment=target_model.environment,
        scope=target_model.scope,
        max_rounds=5,
        max_experiments=5,
    )
    engine = AdversarialEngine(store, policy=policy,
                               planner=default_planner(store))
    engine.research(http_target, rounds=5)

    entries = store.list_journal_entries(target_model.id)
    assert len(entries) == 5
    assert all(e.attack_key.startswith("http-") for e in entries)
    assert all(e.how_it_was_done for e in entries)


# --------------------------------------------------------------------------- #
# Encryption / locking
# --------------------------------------------------------------------------- #

def test_journal_lock_encrypts_at_rest(store):
    engine = JournalEngine(store)
    hyp, exp = _experiment(store)
    engine.record_experiment(
        Target(id="t1", name="x", rules={"base_url": "https://secret.example"}),
        hyp, exp,
    )

    assert not engine.is_locked()
    count = engine.lock("hunter2-secret")
    assert count == 1
    assert engine.is_locked()

    # At-rest rows are encrypted — the plaintext must not be in the DB.
    raw = store.list_journal_entries()
    assert raw[0].how_it_was_done.startswith("v1:")
    assert "plaintext HTTP" not in store._conn.execute(
        "SELECT how_it_was_done FROM journal_entries"
    ).fetchone()[0]


def test_journal_requires_password_when_locked(store):
    from opensystem.journal.crypto import JournalLockedError

    engine = JournalEngine(store)
    hyp, exp = _experiment(store)
    engine.record_experiment(Target(id="t1", name="x"), hyp, exp)
    engine.lock("hunter2-secret")

    with pytest.raises(JournalLockedError):
        engine.list()

    # Wrong password fails.
    with pytest.raises(JournalLockedError):
        engine.list(password="wrong")


def test_journal_unlock_returns_plaintext(store):
    engine = JournalEngine(store)
    hyp, exp = _experiment(store)
    engine.record_experiment(Target(id="t1", name="x"), hyp, exp)
    engine.lock("hunter2-secret")

    assert engine.verify("hunter2-secret")
    assert not engine.verify("wrong")

    entries = engine.list(password="hunter2-secret")
    assert "Methodology" in entries[0].how_it_was_done
    assert not entries[0].how_it_was_done.startswith("v1:")

    count = engine.unlock("hunter2-secret")
    assert count == 1
    assert not engine.is_locked()
    # After unlock, plaintext is readable without a password.
    entries = engine.list()
    assert "Methodology" in entries[0].how_it_was_done


def test_journal_export_requires_password_when_locked(store):
    from opensystem.journal.crypto import JournalLockedError

    engine = JournalEngine(store)
    hyp, exp = _experiment(store)
    engine.record_experiment(
        Target(id="t1", name="x", rules={"base_url": "https://secret.example"}),
        hyp, exp,
    )
    engine.lock("hunter2-secret")

    with pytest.raises(JournalLockedError):
        engine.export_markdown()

    md = engine.export_markdown(password="hunter2-secret")
    assert "Weak Transport Security" in md
    assert "https://secret.example" in md


def test_encrypted_value_roundtrip():
    from opensystem.journal.crypto import (
        decrypt_value,
        encrypt_value,
        is_encrypted,
        verify_password,
    )

    plain = "this is a secret methodology"
    blob = encrypt_value(plain, "owner-pass")
    assert is_encrypted(blob)
    assert decrypt_value(blob, "owner-pass") == plain

    from opensystem.journal.crypto import make_verifier

    salt, verifier = make_verifier("owner-pass")
    assert verify_password("owner-pass", salt, verifier)
    assert not verify_password("wrong", salt, verifier)
