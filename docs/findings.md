# OpenSystem — Findings

This document describes the finding lifecycle and how findings are managed.

## What Is a Finding?

A finding is a **confirmed weakness** with supporting evidence. It is created
from a successful experiment (a hypothesis that tested `SUCCESS`).

A finding contains (see `Finding` in `opensystem/models.py`):

- Finding ID
- Target
- Severity
- Affected component
- Attack hypothesis
- Observed behavior
- Evidence
- Impact
- Reproduction conditions
- Recommended mitigation
- Verification status

## The Finding Lifecycle

```
DISCOVERED
   │
   ▼
CONFIRMED
   │
   ▼
DOCUMENTED
   │
   ▼
MITIGATION
   │
   ▼
VERIFICATION
   │
   ▼
CLOSED
```

| Status | Meaning |
|---|---|
| DISCOVERED | A successful experiment produced the finding. |
| CONFIRMED | The weakness is confirmed with evidence. |
| DOCUMENTED | Reproduction and impact are documented. |
| MITIGATION | A defense has been applied by the defender. |
| VERIFICATION | The fix is being verified (regression testing). |
| CLOSED | The finding is closed. |

## Transition Rules

Transitions are enforced by `FindingEngine.transition()`:

- DISCOVERED → CONFIRMED | CLOSED
- CONFIRMED → DOCUMENTED | CLOSED
- DOCUMENTED → MITIGATION | CLOSED
- MITIGATION → VERIFICATION | CLOSED
- VERIFICATION → CLOSED | MITIGATION
- CLOSED → (no outgoing transitions)

Invalid transitions raise `ValueError`. This prevents the lifecycle from being
corrupted.

## The Rule: A Solved Vulnerability Never Disappears

A finding is **retained in the historical record after it is closed**. Closing
a finding does not delete it. This preserves the research history so future
attacks can reason about what was found, fixed, and verified.

## Finding → Defense → Regression

When the defender patches a finding:

1. A `Defense` is recorded against the finding.
2. The finding transitions to MITIGATION (then VERIFICATION, then CLOSED).
3. A regression test re-tests the original hypothesis; the outcome proves the
   fix holds.
4. The defense is recorded in knowledge with provenance.

## CLI

- `opensystem finding list` — list findings (optionally only open ones)
- `opensystem finding transition <id> <status>` — advance the lifecycle

## Status Vocabulary

Findings are reported with evidence-based statuses. OpenSystem never claims a
target is "secure" — it reports what was found, tested, blocked, and what
remains untested.
