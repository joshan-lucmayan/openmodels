"""OpenSystem version."""

__version__ = "0.3.1"

# Schema version for the knowledge store. Bump when migrations are required.
# 2 — v0.3 proof-session, impact-verification, and case-study tables.
# 3 — structured finding identities (objective/actor/resource/interface)
#     and campaign_id on attack paths.
SCHEMA_VERSION = 3
