# Target Adapters

**Module**: `opensystem/target/registry.py`

## Responsibility

Registry and lifecycle for concrete target adapter implementations.

## API

- `TargetRegistry()` — constructor; auto-discovers built-in adapters.
- `names()` — list registered adapter names.
- `get(name)` — return the adapter class.
- `create(name, **kwargs)` — instantiate an adapter.

## Registration

Adapters are registered by decorating or calling `register_target()`:

```python
@register_target
class WebAppAdapter(TargetAdapter):
    name = "webapp"
```

## Built-in

- `http` — `HttpSiteTarget`, the real HTTP(S) adapter for live web targets
  (see `docs/components/http-target.md`).

## Key Design Decisions

- Registration happens at import time (the `register_target(...)` calls in the
  package).
- The registry is a singleton (`_registry` module-level dict) so the engine
  and CLI share the same set.