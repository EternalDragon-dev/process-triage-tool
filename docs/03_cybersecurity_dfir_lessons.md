# 03 — Cybersecurity and DFIR Lessons
## 1) What is DFIR?
**Digital Forensics and Incident Response (DFIR)** combines:
- incident detection and containment,
- forensic evidence collection,
- timeline reconstruction,
- post-incident reporting.

Sentinel Loop supports triage and evidence consistency in early-response phases.

## 2) Indicator, artifact, finding
### Indicator
A suspicious signal (for example: outbound traffic to high-risk ports).

### Artifact
Raw evidence source (process row, network connection row, persistence entry).

### Finding
A structured output produced by evaluating artifacts against rules.

## 3) Severity vs confidence
### Severity
Potential impact level (`HIGH`, `MEDIUM`, `LOW`).

### Confidence
How certain the system is about the finding given current evidence.

Sentinel Loop teaches an important rule:
**Severity and confidence are not the same thing.**

## 4) Why cross-domain corroboration matters
A single suspicious process may be noisy.
The same process + suspicious network behavior is stronger evidence.
Add persistence evidence and confidence may rise again.

This mirrors real analyst practice: independent evidence sources reduce false positives.

## 5) Chain of evidence
In forensics, you must preserve:
- what data was analyzed,
- what logic was applied,
- what output was generated,
- when each step occurred.

Sentinel Loop implements this through JSONL audit events and report integrity hashes.

## 6) False positives and false negatives
### False positive
Benign behavior flagged as malicious.

### False negative
Malicious behavior missed.

Self-correction logic helps reduce false positives by downgrading uncorroborated findings.

## 7) Example scenario
1. Process rule flags suspicious path.
2. Network rules find matching external beaconing for same PID.
3. Correction engine upgrades confidence (`CONFIRMED_UPWARD`).
4. If persistence evidence is missing, confidence may stay below escalation threshold.

## 8) Practical SOC usage
- Run wrappers on periodic exports.
- Sort by corrected confidence and correction type.
- Investigate `ESCALATED` and high-confidence findings first.
- Archive audit logs and hashes in case records.
