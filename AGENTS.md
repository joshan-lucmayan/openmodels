# AGENTS.md

Guidance for AI agents and contributors working in this repository.

## Project

OpenSystem is an evolving adversarial intelligence platform. It continuously
searches for weaknesses in complex systems, learns from both success and
failure, and evolves. See `docs/vision.md`.

## Commands

```console
# Setup (first time)
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Run tests
.venv/bin/python -m pytest

# Run the CLI
.venv/bin/opensystem --help
```

## Conventions

- **Language**: Python 3.11+. Use pydantic v2 models for all entities.
- **Entities**: define new entities in `opensystem/models.py` as pydantic
  `BaseModel` classes. Never represent research process as unstructured text.
- **Persistence**: all persistence goes through `KnowledgeStore` in
  `opensystem/knowledge/store.py`. Add CRUD + analytical query methods there.
- **Targets**: new target classes implement `TargetAdapter` and are
  registered via `register_target()`.
- **Attacks**: new attack families are registered as `AttackStrategy` (or a
  strategy factory) on the `AttackPlanner`.
- **Policy**: the reasoning engine must never embed authorization logic. All
  authorization lives in `opensystem/policy/`.
- **Tests**: every implemented component must have at least one test. Run the
  suite with `.venv/bin/python -m pytest`.
- **Docs**: architectural decisions go in `docs/adr/` (ADR style). Component
  responsibilities go in `docs/components/`.
- **No fake functionality**: do not build placeholder/pretend features. Build
  the smallest real foundation that can evolve.

## Architecture at a Glance

```
core/engine.py       AdversarialEngine — the loop
target/              TargetAdapter + adapters + registry
observation/         ObservationEngine
hypothesis/          HypothesisEngine
attack/              AttackPlanner + strategies
experiment/          ExperimentEngine
evidence/            EvidenceCollector
finding/             FindingEngine (lifecycle)
evolution/           EvolutionEngine
knowledge/           KnowledgeStore (SQLite)
policy/              Policy + PolicyEnforcer
cli/                 CLI commands
```

## Testing

```console
.venv/bin/python -m pytest -v
```

Run a single file: `.venv/bin/python -m pytest tests/test_loop.py`

## Git

- This repository should not contain: `opensystem.db`, `.os/`, `.venv/`,
  secrets, or credentials (see `.gitignore`).
