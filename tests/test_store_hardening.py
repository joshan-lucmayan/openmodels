"""Tests for knowledge-store hardening: write semantics, transactions, queries."""

from __future__ import annotations

import pytest

from opensystem.models import Knowledge, KnowledgeKind


def test_append_only_records_keep_first_version(store):
    """Audit records never lose their original content to a re-save."""
    k = Knowledge(
        id="fixed-id", kind=KnowledgeKind.ASSUMPTION,
        content="original record", target_id="t1",
    )
    store.save_knowledge(k)
    overwritten = k.model_copy(update={"content": "overwritten record"})
    store.save_knowledge(overwritten)

    results = store.search_knowledge("record", target_id="t1")
    assert len(results) == 1
    assert results[0].content == "original record"


def test_transaction_commits_together(store):
    with store.transaction():
        store.save_knowledge(
            Knowledge(kind=KnowledgeKind.PATTERN, content="alpha-content",
                      target_id="t1")
        )
        store.save_knowledge(
            Knowledge(kind=KnowledgeKind.PATTERN, content="beta-content",
                      target_id="t1")
        )
    assert len(store.search_knowledge("alpha-content")) == 1
    assert len(store.search_knowledge("beta-content")) == 1


def test_transaction_rolls_back_on_error(store):
    with pytest.raises(RuntimeError), store.transaction():
        store.save_knowledge(
            Knowledge(kind=KnowledgeKind.PATTERN, content="rolled-content",
                      target_id="t1")
        )
        raise RuntimeError("boom")
    assert store.search_knowledge("rolled-content") == []


def test_nested_transactions_commit_at_outermost(store):
    with store.transaction():
        with store.transaction():
            store.save_knowledge(
                Knowledge(kind=KnowledgeKind.PATTERN, content="nested-content",
                          target_id="t1")
            )
        # Visible on the same connection inside the outer block either way.
        assert len(store.search_knowledge("nested-content")) == 1
    assert len(store.search_knowledge("nested-content")) == 1


def test_target_environment_and_scope_round_trip(store, http_target):
    target = http_target.discover()
    store.save_target(target)
    stored = store.get_target(target.id)
    assert stored.environment == "test"
    assert stored.scope is not None