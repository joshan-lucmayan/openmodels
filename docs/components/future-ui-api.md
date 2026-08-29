# Future UI / API Layer

**Module**: *not yet implemented*

## Responsibility

Future web UI and REST API for OpenSystem.

## Planned Architecture

```
Web UI (React/Vue)  ──▶ REST API ──▶ Adversarial Engine
                                        │
                                        ▼
                                    Knowledge Store
```

## Design Constraints

- The REST API should be a thin layer over the existing engine/store API.
- Authentication for the API uses the existing policy layer (API tokens map
  to policies).
- The UI is a consumer of the API, not a peer of the engine.

## Endpoints (planned)

- `GET /targets` — list targets
- `POST /research` — start a research session (async, returns session ID)
- `GET /research/{id}` — session status and report
- `GET /findings` — list findings
- `GET /knowledge` — search knowledge
- `POST /findings/{id}/transition` — advance finding lifecycle

## When

This is a **v0.5+** concern. Not before the core reasoning engine,
extensibility, and multi-target support are stable.