# Target Adapters

**Module**: `openmodels/target/registry.py`

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

- `mock` — `MockTarget`, the deterministic v0.1 adapter.

## Key Design Decisions

- Registration happens at import time (the `register_target(MockTarget)` call
  in the package).
- The registry is a singleton (`_registry` module-level dict) so the engine
  and CLI share the same set.