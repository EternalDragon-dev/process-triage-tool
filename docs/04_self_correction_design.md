# 04 — Self-Correction Design
## Why a correction layer exists
Rule-based detection is useful but incomplete. Single-domain signals are often ambiguous.
The correction layer is designed to answer:
- “Do other evidence domains agree?”
- “Should confidence be revised?”

## Correction flow
1. Run process/network/persistence triage independently.
2. Build correlation indexes (PID and process-name linkage).
3. Evaluate corroboration patterns.
4. Apply confidence deltas.
5. Emit correction events and corrected findings.

## Correction types and intent
### `CONFIRMED_UPWARD`
Use when another domain independently supports the finding.

### `UNCONFIRMED`
Use when a finding has no supporting evidence from other domains.

### `ESCALATED`
Use when multiple corroborating domains indicate stronger compromise likelihood.

### `DOWNGRADED`
Use when evidence weakens or contradicts initial suspicion.

## Example confidence revision
- Original finding confidence: `0.76`
- Corroborating network + process match: `+0.10`
- Revised confidence: `0.86`

## Design constraints
- Deterministic outcomes for forensic repeatability.
- Explainable corrections with explicit reasons.
- No hidden model state.
- Lightweight runtime overhead suitable for constrained hardware.

## Engineering trade-offs
### Pros
- Better triage prioritization
- Lower one-shot false-positive impact
- Stronger explainability for analysts and judges

### Cons
- Requires normalized multi-domain input
- Correlation quality depends on data quality (PID/process lineage consistency)

## Suggested extension ideas
- Add hostname/session-aware correlations
- Add temporal windows for event sequence weighting
- Add confidence decay when events become stale
- Add optional threat-intel enrichment stage
