# 06 — Glossary
## Core project terms
### Artifact
Raw input evidence (for example, a process row, network connection row, or persistence entry).

### Finding
A structured suspicious output produced by applying detection rules to artifacts.

### Confidence factor
A numeric estimate of how strongly current evidence supports a finding.

### Correction event
A record showing how and why confidence changed after cross-domain verification.

### Integrity hash
`sha256` digest of report payload used to verify content integrity.

## Software engineering terms
### Modularity
Design principle of dividing a system into focused components.

### Separation of concerns
Keeping different problem types in different modules.

### Determinism
Same input always produces the same output.

### Data contract
An agreed structure and type expectation for exchanged data.

### Refactoring
Improving structure without changing intended behavior.

### Observability
Ability to understand internal behavior from emitted logs/events.

## Cybersecurity / DFIR terms
### DFIR
Digital Forensics and Incident Response.

### Indicator of compromise (IOC)
A signal suggesting potential malicious activity.

### False positive
Benign activity incorrectly flagged as suspicious.

### False negative
Malicious activity not detected.

### Triage
Prioritizing what to investigate first.

### Chain of evidence
Documented sequence showing how evidence was collected, processed, and interpreted.

## Sentinel Loop correction labels
### `CONFIRMED_UPWARD`
Confidence increased because another domain corroborated the finding.

### `UNCONFIRMED`
Confidence reduced because corroboration was not found.

### `ESCALATED`
Confidence increased strongly due to multi-domain supporting evidence.

### `DOWNGRADED`
Confidence reduced because evidence weakens or contradicts initial suspicion.
