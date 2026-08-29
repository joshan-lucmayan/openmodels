# OpenSystem — Threat Model

This document analyzes threats to **OpenSystem itself** and the operational
environment it runs in. It is distinct from the attack model (what OpenSystem
does to its targets) and the security model (how deployments authorize it).

## Asset Classes

| Asset | Description | Confidentiality | Integrity | Availability |
|---|---|---|---|---|
| Knowledge store | Hypotheses, experiments, evidence, findings, credentials references | High | High | Medium |
| Target model | The modelled target (interfaces, assets, trust boundaries) | High | High | Medium |
| Evidence | Captured requests/responses/state | High | High | Medium |
| Policy configuration | What is authorized | High | High | Medium |
| Reasoning engine | The code itself | Medium | High | High |
| Deployment identity | Credentials used against targets | Critical | Critical | Medium |

## Principal Threats

### T1 — Knowledge exfiltration
The knowledge store may contain sensitive observations about real targets.
**Mitigations:** store is local SQLite; policy layer limits what is collected;
credentials are referenced, never stored verbatim; the `.gitignore` excludes
data files. Future: encryption at rest.

### T2 — Prompt/action injection through a target
A hostile target could craft observations designed to manipulate OpenSystem'
reasoning (the adversarial analogue of prompt injection for attacker agents).
**Mitigations:** v0.1 reasoning is deterministic and strategy-driven; observed
data is treated as data, not instructions. Future: separate untrusted
observation content from trusted control flow; canonicalize evidence.

### T3 — Unauthorized operation execution
A misconfigured policy could allow tests against targets that were not
authorized, or destructive actions that were not permitted.
**Mitigations:** `PolicyEnforcer` is the single gate; every test checks policy;
destructive actions are denied by default; policy is scoped by target name.
This is the most important control — see [`security-model.md`](security-model.md).

### T4 — Poisoning of the knowledge base
An attacker (or a malicious target) could inject false knowledge that misleads
future research (e.g., marking a real weakness as "blocked").
**Mitigations:** every knowledge record carries `provenance`; every evolution
event records trigger + reason; findings require experiment evidence.
Future: signed/verified provenance chains.

### T5 — Supply chain compromise of OpenSystem itself
Dependency substitution in the OpenSystem toolchain (see the
`dependency-supply-chain` attack class — OpenSystem must eat its own dog food).
**Mitigations:** pinned dependencies in lockfiles; review of the dependency
tree. The project models this class explicitly for its targets.

### T6 — Resource exhaustion
Unbounded research sessions could consume excessive CPU/storage.
**Mitigations:** policy `max_rounds` / `max_experiments` bounds; session stop
reasons recorded.

## Trust Boundaries

```
[ Reasoning engine ]         — trusted, never modified by research
        │
        ▼
[ Policy enforcement ]       — the gate; single decision point
        │
        ▼
[ Target adapter ]           — semi-trusted; converts target reality
        │
        ▼
[ Target ]                   — UNTRUSTED (assume hostile)
```

OpenSystem treats every target as hostile. The target can return arbitrary
observations and evidence. These are stored as data and never executed.

## Assumptions

- A1: The operator configures the policy honestly and correctly.
- A2: The deployment environment is single-operator (v0.1).
- A3: The host filesystem protects the knowledge store (POSIX permissions).
- A4: Credentials used against targets are provisioned out of band.

## Out of Scope (v0.1)

- Multi-operator / multi-tenant deployments.
- Network exposure of the store or a UI.
- Hardware-based attestation.

## Threat-to-control mapping

| Threat | Primary control |
|---|---|
| T1 | Local store, no credentials stored, exclusions |
| T2 | Deterministic reasoning; data/instruction separation |
| T3 | PolicyEnforcer as single gate |
| T4 | Provenance on all knowledge and evolution records |
| T5 | Dependency pinning |
| T6 | Session bounds |
