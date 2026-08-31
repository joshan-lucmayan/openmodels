"""OpenSystem version."""

__version__ = "0.4.1"

# Schema version for the knowledge store. Bump when migrations are required.
# 4 — v0.4: drop mock-boundary-era tables (defenses, regressions, campaigns,
#     proof sessions, impact verifications, case studies, actors, resources,
#     entitlements, invariants, objectives, surfaces, paths).
# 5 — v0.4.1: journal_entries table (attack journaling).
SCHEMA_VERSION = 5
