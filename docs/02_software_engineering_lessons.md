# 02 — Software Engineering Lessons from Sentinel Loop
## 1) Modularity
### Definition
**Modularity** is separating a system into focused components with clear responsibilities.

### Sentinel Loop example
- Loaders parse and normalize input.
- Rules evaluate suspicious conditions.
- Triage orchestrators assemble reports.
- Correction engine revises confidence across domains.

### Why it matters
- Easier testing and debugging
- Safer refactoring
- Better collaboration across contributors

## 2) Separation of concerns
### Definition
Each layer should solve one category of problem.

### Example mapping
- Data model concerns: `models.py`
- Parsing concerns: `loader.py`
- Detection concerns: `rules.py`
- Report concerns: `triage.py`
- Audit concerns: `audit.py`
- UX/entrypoint concerns: `*_main.py`

## 3) Determinism in security pipelines
### Definition
A deterministic component produces the same output given the same input.

### Application in Sentinel Loop
- Rule evaluation is deterministic.
- Correction delta logic is deterministic.
- Report integrity hashing is deterministic.

### Benefit
Determinism supports forensic reproducibility and easier root-cause analysis.

## 4) Data contracts
### Definition
A **data contract** defines required fields and expected data types between modules.

### Example
Network triage expects fields such as `pid`, `remote_address`, `remote_port`, `state`.

### Benefit
Contracts reduce integration drift and make validation straightforward.

## 5) Auditability-first engineering
### Definition
Auditability means a system can explain what happened and why.

### Sentinel Loop implementation
The `@audit_tool` decorator logs:
- invocation start
- invocation completion
- tool identity
- reasoning
- summarized output

### Lesson
In security software, observability and auditability are core features, not optional add-ons.

## 6) Hash-based integrity
### Definition
A report hash ensures output content has not silently changed.

### Use case
Store report + `sha256` hash together in case records. Recompute hash later to verify integrity.

## 7) Progressive refactoring
Sentinel Loop evolved from simple wrappers to:
- modular packages,
- MCP integration,
- correction engine,
- audit decorator.

This is a good example of incremental architecture maturation without rewriting everything at once.
