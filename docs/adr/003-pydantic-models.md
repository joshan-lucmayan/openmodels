# ADR 003 — Structured Entities via Pydantic

- **Status**: Accepted
- **Date**: 2026-08-29

## Context

OpenModels requires that the research process be represented as explicit,
structured, persistable entities — never unstructured text. The entities
(hypothesis, observation, experiment, evidence, finding, defense, regression,
knowledge, evolution event) must validate, serialize cleanly to SQLite, and
support future reasoning.

## Options Considered

| Option | Assessment |
|---|---|
| **Pydantic v2 models** | Validation, typed fields, serialization, already installed. |
| Dataclasses | No validation, more manual serialization work. |
| Plain dicts | No structure, no validation — violates the requirement. |
| SQLAlchemy ORM models | Heavier; couples entity definitions to the DB layer. |

## Decision

Define all core entities as **pydantic v2 `BaseModel`** classes in a single
`openmodels/models.py` module.

## Rationale

1. **Validation**: pydantic enforces types and enums at the boundary,
   preventing malformed entities from entering the store.
2. **Persistence decoupling**: models serialize to/from SQLite rows inside
   `KnowledgeStore`, keeping entities free of DB concerns and the store
   swappable.
3. **Already installed** in the environment.
4. **Future reasoning**: typed, structured entities are directly usable by
   future reasoning components (LLM-backed planners, graph analysis) without
   re-parsing free text.

## Consequences

- Serialization is explicit (JSON for dict fields, ISO strings for
  timestamps) rather than automatic — a small cost, contained in the store.
- Entities must be kept free of DB-specific fields to preserve the seam.

## Rejected

- **Dataclasses**: insufficient validation for a security-research data model.
- **SQLAlchemy ORM**: couples models to SQL; heavier than needed now. Can be
  introduced later behind `KnowledgeStore`.
