"""Journal engine — records every attack OpenSystem performs.

Each entry documents one executed attack: the attack type, its documented
methodology (from the playbook), the runtime specifics (target URL, test
parameters, observed result), the outcome, and the collected evidence. The
journal is the complete, auditable account of what was tested and how.

The journal can be **locked** with the owner's password. When locked, the
sensitive fields of every entry (how_it_was_done, observed_result, detail,
summary, attack_name, family, target_url) are encrypted at rest with
AES-256-GCM. Reading requires the same password.
"""

from __future__ import annotations

import json

from opensystem.journal.crypto import (
    JournalDecryptError,
    JournalLockedError,
    decrypt_value,
    encrypt_value,
    is_encrypted,
    make_verifier,
    verify_password,
)
from opensystem.journal.playbook import ATTACK_KEYS, playbook_for
from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import Experiment, Hypothesis, JournalEntry, Target

_SENSITIVE_FIELDS = (
    "target_url", "attack_name", "family", "summary", "how_it_was_done",
    "observed_result",
)


class JournalEngine:
    """Persists and queries detailed attack records, optionally encrypted."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    # ------------------------------------------------------------------ #
    # Locking / encryption
    # ------------------------------------------------------------------ #

    def is_locked(self) -> bool:
        return self._store.get_metadata("journal_encrypted") == "1"

    def lock(self, password: str) -> int:
        """Encrypt all journal entries with the owner password.

        Returns the number of entries encrypted.
        """
        salt_hex, verifier_hex = make_verifier(password)
        entries = self._store.list_journal_entries()
        for entry in entries:
            self._encrypt_entry(entry, password)
        self._store.set_metadata("journal_encrypted", "1")
        self._store.set_metadata("journal_salt", salt_hex)
        self._store.set_metadata("journal_verifier", verifier_hex)
        return len(entries)

    def unlock(self, password: str) -> int:
        """Decrypt all journal entries, returning them to plaintext.

        Returns the number of entries decrypted.
        """
        self._require_correct_password(password)
        entries = self._store.list_journal_entries()
        for entry in entries:
            decrypted = self._decrypt_entry(entry, password)
            self._persist_entry_fields(decrypted)
        self._store.delete_metadata("journal_encrypted")
        self._store.delete_metadata("journal_salt")
        self._store.delete_metadata("journal_verifier")
        return len(entries)

    def verify(self, password: str) -> bool:
        """Return True if the password matches the stored verifier."""
        salt = self._store.get_metadata("journal_salt")
        verifier = self._store.get_metadata("journal_verifier")
        if not salt or not verifier:
            return False
        return verify_password(password, salt, verifier)

    # ------------------------------------------------------------------ #
    # Recording
    # ------------------------------------------------------------------ #

    def record_experiment(
        self,
        target_model: Target,
        hypothesis: Hypothesis,
        experiment: Experiment,
        detail: dict | None = None,
    ) -> JournalEntry:
        """Record a completed experiment as a journal entry.

        The methodology comes from the playbook; the runtime specifics come
        from the actual experiment (test parameters, observed result) and
        the collected evidence.
        """
        attack_key = hypothesis.origin.replace("strategy:", "")
        p = playbook_for(attack_key) or {}

        how = self._build_how(p, experiment, detail)

        entry = JournalEntry(
            target_id=target_model.id,
            target_url=(target_model.rules or {}).get("base_url", ""),
            attack_key=attack_key,
            attack_name=p.get("name", attack_key),
            family=p.get("family", ""),
            outcome=experiment.outcome,
            summary=self._build_summary(p, experiment),
            how_it_was_done=how,
            observed_result=experiment.observed_result,
            detail=detail or {},
            evidence_ids=experiment.evidence_ids,
            hypothesis_id=hypothesis.id,
            experiment_id=experiment.id,
        )
        self._store.save_journal_entry(entry)
        return entry

    def _build_how(self, playbook: dict, experiment: Experiment, detail: dict | None) -> str:
        parts = []
        if playbook.get("how_it_was_done"):
            parts.append("## Methodology")
            parts.append(playbook["how_it_was_done"])
        parts.append("## Execution")
        parts.append(
            f"- Test name: `{experiment.test.name}`"
        )
        params = experiment.test.parameters or {}
        if params:
            param_str = ", ".join(f"{k}={v!r}" for k, v in params.items())
            parts.append(f"- Parameters: {param_str}")
        if experiment.observed_result:
            parts.append(f"- Observed result: {experiment.observed_result}")
        if detail:
            detail_str = ", ".join(f"{k}={v!r}" for k, v in detail.items())
            parts.append(f"- Detail: {detail_str}")
        return "\n".join(parts)

    def _build_summary(self, playbook: dict, experiment: Experiment) -> str:
        label = {
            "SUCCESS": "confirmed",
            "FAILURE": "blocked",
            "BLOCKED": "policy-blocked",
            "INCONCLUSIVE": "inconclusive",
            "ERROR": "error",
        }.get(experiment.outcome.value, experiment.outcome.value)
        name = playbook.get("name", experiment.test.name)
        return f"{name}: {label}"

    # ------------------------------------------------------------------ #
    # Queries (decrypt-on-read if locked)
    # ------------------------------------------------------------------ #

    def list(self, target_id: str | None = None, attack_key: str | None = None,
             password: str | None = None):
        raw = self._store.list_journal_entries(target_id, attack_key)
        if self.is_locked():
            self._require_correct_password(password)
            return [self._decrypt_entry(e, password) for e in raw]
        return raw

    def get(self, entry_id: str, password: str | None = None):
        raw = self._store.get_journal_entry(entry_id)
        if raw is None:
            return None
        if self.is_locked():
            self._require_correct_password(password)
            return self._decrypt_entry(raw, password)
        return raw

    # ------------------------------------------------------------------ #
    # Internal encryption helpers
    # ------------------------------------------------------------------ #

    def _encrypt_entry(self, entry: JournalEntry, password: str) -> None:
        updates = {}
        for field in _SENSITIVE_FIELDS:
            val = getattr(entry, field, "")
            if val and not is_encrypted(val):
                updates[field] = encrypt_value(val, password)
        if entry.detail and not isinstance(entry.detail, str):
            updates["detail"] = encrypt_value(
                json.dumps(entry.detail, default=str), password
            )
        if updates:
            self._update_entry_fields(entry.id, updates)

    def _decrypt_entry(self, entry: JournalEntry, password: str) -> JournalEntry:
        """Decrypt sensitive fields of a JournalEntry in-place."""
        for field in _SENSITIVE_FIELDS:
            val = getattr(entry, field, "")
            if is_encrypted(val):
                setattr(entry, field, decrypt_value(val, password))
        detail_val = getattr(entry, "detail", {})
        if isinstance(detail_val, str) and is_encrypted(detail_val):
            try:
                entry.detail = json.loads(decrypt_value(detail_val, password))
            except (json.JSONDecodeError, JournalDecryptError):
                entry.detail = {}
        return entry

    def _persist_entry_fields(self, entry: JournalEntry) -> None:
        """Write the entry's sensitive fields back to the store as plaintext."""
        updates = {}
        for field in _SENSITIVE_FIELDS:
            val = getattr(entry, field, "")
            if not is_encrypted(val):
                updates[field] = val
        if not isinstance(entry.detail, str):
            updates["detail"] = json.dumps(entry.detail, default=str)
        if updates:
            self._update_entry_fields(entry.id, updates)

    def _update_entry_fields(self, entry_id: str, updates: dict) -> None:
        """Directly update specific fields on a journal entry row."""
        if not updates:
            return
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values())
        values.append(entry_id)
        self._store._conn.execute(
            f"UPDATE journal_entries SET {set_clause} WHERE id = ?",
            values,
        )
        self._store._commit()

    def _require_correct_password(self, password: str | None) -> None:
        if password is None:
            raise JournalLockedError(
                "The journal is locked. Provide the owner password with "
                "--password."
            )
        if not self.verify(password):
            raise JournalLockedError("Wrong journal password.")

    # ------------------------------------------------------------------ #
    # Export
    # ------------------------------------------------------------------ #

    def export_markdown(self, target_id: str | None = None,
                        password: str | None = None) -> str:
        """Render the journal as a detailed Markdown report."""
        entries = self.list(target_id, password=password)
        lines = [
            "# OpenSystem Attack Journal",
            "",
            f"Total entries: {len(entries)}",
            "",
        ]
        by_key: dict[str, list] = {}
        for e in entries:
            by_key.setdefault(e.attack_key, []).append(e)

        for key in ATTACK_KEYS:
            if key not in by_key:
                continue
            entries_for_key = by_key[key]
            lines.append(f"## {entries_for_key[0].attack_name} (`{key}`)")
            lines.append("")
            for e in entries_for_key:
                lines.append(f"### Entry {e.id[:8]} — {e.created_at.isoformat()}")
                lines.append("")
                lines.append(f"**Outcome:** {e.outcome.value}")
                lines.append("")
                if e.target_url:
                    lines.append(f"**Target:** {e.target_url}")
                    lines.append("")
                lines.append(e.how_it_was_done)
                lines.append("")

        for key, entries_for_key in by_key.items():
            if key in ATTACK_KEYS:
                continue
            lines.append(f"## {entries_for_key[0].attack_name} (`{key}`)")
            lines.append("")
            for e in entries_for_key:
                lines.append(f"### Entry {e.id[:8]} — {e.created_at.isoformat()}")
                lines.append("")
                lines.append(f"**Outcome:** {e.outcome.value}")
                lines.append("")
                lines.append(e.how_it_was_done)
                lines.append("")
        return "\n".join(lines)

    def playbook_markdown(self, attack_key: str | None = None) -> str:
        """Render the documented methodology for attack types as Markdown."""
        keys = [attack_key] if attack_key else ATTACK_KEYS
        lines = ["# OpenSystem Attack Playbook", ""]
        for key in keys:
            p = playbook_for(key)
            if p is None:
                continue
            lines.append(f"## {p['name']} (`{key}`)")
            lines.append("")
            lines.append(f"**Family:** {p['family']}")
            lines.append("")
            lines.append(f"**Summary:** {p['summary']}")
            lines.append("")
            lines.append("**How it is done:**")
            lines.append("")
            lines.append(p["how_it_was_done"])
            lines.append("")
            lines.append("**Why it matters:**")
            lines.append("")
            lines.append(p["why_it_matters"])
            lines.append("")
        return "\n".join(lines)