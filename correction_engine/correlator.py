"""
Cross-reference correlator for the Hypothesis-Verification-Correction loop.

Logic applied (deterministic, no LLM required at this layer):

  P → N  (Process ↔ Network, PID-keyed)
        A suspicious process with a matching network finding for the same PID
        gets CONFIRMED_UPWARD.  If it ALSO has a persistence finding by name,
        it is ESCALATED instead.

  P → S  (Process ↔ Persistence, name-keyed)
        A suspicious process whose name appears inside a persistence artifact
        command string is ESCALATED (active process + installed persistence).

  N → P  (Network ↔ Process, PID-keyed)
        A HIGH network finding whose PID belongs to a process with no triage
        findings is DOWNGRADED slightly (clean-looking process opening C2 port
        is suspicious, but less confident without process-side corroboration).

  S → P  (Persistence ↔ Process, name-keyed)
        A HIGH persistence artifact whose command contains a currently-running
        *flagged* process name is ESCALATED.

  Anything that fails to match any cross-reference is UNCONFIRMED.
"""
from __future__ import annotations

from collections import defaultdict

from correction_engine.models import (
    CONFIRMED_UPWARD,
    DOWNGRADED,
    ESCALATED,
    UNCONFIRMED,
    CorrectedFinding,
    CorrectionEvent,
    apply_correction,
    baseline_confidence,
)


def _safe_cf(finding_dict: dict) -> float:
    """Return confidence_factor if present, else derive from severity."""
    cf = finding_dict.get("confidence_factor")
    if cf is not None:
        return float(cf)
    return baseline_confidence(finding_dict.get("severity", "LOW"))


def run_correlations(
    process_findings: list[dict],
    network_findings: list[dict],
    persistence_findings: list[dict],
) -> tuple[list[CorrectedFinding], list[CorrectionEvent]]:
    """
    Cross-reference all three finding sets and return:
      - corrected_findings  (one entry per original finding, with revised confidence)
      - correction_events   (full audit trail of every hypothesis correction)
    """
    corrected: list[CorrectedFinding] = []
    events: list[CorrectionEvent] = []

    # ── Build lookup indexes ─────────────────────────────────────────────────
    # Network findings grouped by PID
    net_by_pid: dict[int, list[dict]] = defaultdict(list)
    for nf in network_findings:
        net_by_pid[nf.get("pid", -1)].append(nf)

    # Persistence findings grouped by lower-case tokens in their command
    # We'll do a loose substring match: if the process name appears in the command.
    # Build a list of (command_lower, finding_dict) pairs.
    persistence_commands: list[tuple[str, dict]] = [
        (pf.get("evidence", {}).get("command", "").lower(), pf)
        for pf in persistence_findings
    ]

    # Flagged process PIDs (any process finding present for that PID)
    flagged_process_pids: set[int] = {pf.get("pid", -1) for pf in process_findings}
    flagged_process_names: set[str] = {
        pf.get("process_name", "").lower() for pf in process_findings if pf.get("process_name")
    }

    # ── Pass 1: Correct Process findings ────────────────────────────────────
    for pf in process_findings:
        pid = pf.get("pid", -1)
        proc_name = pf.get("process_name", "").lower()
        severity = pf.get("severity", "LOW")
        original_cf = _safe_cf(pf)
        corroborating: list[dict] = []

        net_hits = net_by_pid.get(pid, [])
        persist_hits = [
            pdata
            for cmd_lower, pdata in persistence_commands
            if proc_name and proc_name in cmd_lower
        ]

        if net_hits and persist_hits:
            # Worst case: active process + network activity + persistence installed
            correction_type = ESCALATED
            reason = (
                f"Process '{pf.get('process_name')}' (PID {pid}) has matching network "
                f"findings AND appears in {len(persist_hits)} persistence artifact(s). "
                f"Active threat with installed persistence confirmed."
            )
            corroborating = [{"domain": "network", "finding": n} for n in net_hits] + [
                {"domain": "persistence", "finding": p} for p in persist_hits
            ]
        elif net_hits:
            correction_type = CONFIRMED_UPWARD
            reason = (
                f"Process '{pf.get('process_name')}' (PID {pid}) corroborated by "
                f"{len(net_hits)} network finding(s) for the same PID."
            )
            corroborating = [{"domain": "network", "finding": n} for n in net_hits]
        elif persist_hits:
            correction_type = ESCALATED
            reason = (
                f"Process '{pf.get('process_name')}' found in "
                f"{len(persist_hits)} persistence artifact command(s). "
                f"Process has established persistence."
            )
            corroborating = [{"domain": "persistence", "finding": p} for p in persist_hits]
        else:
            correction_type = UNCONFIRMED
            reason = (
                f"No corroborating network or persistence evidence found for "
                f"process '{pf.get('process_name')}' (PID {pid}). "
                f"Finding stands but confidence reduced."
            )

        revised_cf = apply_correction(original_cf, correction_type)
        event = CorrectionEvent(
            finding_domain="process",
            finding_rule_id=pf.get("rule_id", "UNKNOWN"),
            correction_type=correction_type,
            original_confidence=original_cf,
            revised_confidence=revised_cf,
            reasoning=reason,
            corroborating_evidence=corroborating,
        )
        events.append(event)
        corrected.append(
            CorrectedFinding(
                source_domain="process",
                rule_id=pf.get("rule_id", "UNKNOWN"),
                severity=severity,
                message=pf.get("message", ""),
                original_confidence=original_cf,
                revised_confidence=revised_cf,
                correction_type=correction_type,
                correction_reason=reason,
                original_finding=pf,
                corroborating_evidence=corroborating,
            )
        )

    # ── Pass 2: Correct Network findings ────────────────────────────────────
    for nf in network_findings:
        pid = nf.get("pid", -1)
        severity = nf.get("severity", "LOW")
        original_cf = _safe_cf(nf)
        corroborating: list[dict] = []

        if pid in flagged_process_pids:
            # Process side also flagged this PID — strong corroboration
            matching_proc_findings = [pf for pf in process_findings if pf.get("pid") == pid]
            correction_type = CONFIRMED_UPWARD
            reason = (
                f"Network finding for PID {pid} corroborated by "
                f"{len(matching_proc_findings)} process-side finding(s) for the same PID."
            )
            corroborating = [{"domain": "process", "finding": p} for p in matching_proc_findings]
        else:
            # Network activity with no flagged process — could indicate hollowing/injection
            # Still suspicious but we cannot confirm from process triage alone
            correction_type = DOWNGRADED
            reason = (
                f"Network finding for PID {pid} has no matching suspicious process finding. "
                f"Process may appear legitimate (possible process hollowing). "
                f"Confidence reduced; manual verification recommended."
            )

        revised_cf = apply_correction(original_cf, correction_type)
        event = CorrectionEvent(
            finding_domain="network",
            finding_rule_id=nf.get("rule_id", "UNKNOWN"),
            correction_type=correction_type,
            original_confidence=original_cf,
            revised_confidence=revised_cf,
            reasoning=reason,
            corroborating_evidence=corroborating,
        )
        events.append(event)
        corrected.append(
            CorrectedFinding(
                source_domain="network",
                rule_id=nf.get("rule_id", "UNKNOWN"),
                severity=severity,
                message=nf.get("message", ""),
                original_confidence=original_cf,
                revised_confidence=revised_cf,
                correction_type=correction_type,
                correction_reason=reason,
                original_finding=nf,
                corroborating_evidence=corroborating,
            )
        )

    # ── Pass 3: Correct Persistence findings ────────────────────────────────
    for pdata in persistence_findings:
        severity = pdata.get("severity", "LOW")
        original_cf = _safe_cf(pdata)
        command = pdata.get("evidence", {}).get("command", "").lower()
        corroborating: list[dict] = []

        matched_proc_names = [
            name for name in flagged_process_names if name and name in command
        ]

        if matched_proc_names:
            correction_type = ESCALATED
            reason = (
                f"Persistence artifact command contains flagged process name(s) "
                f"{matched_proc_names!r}. Active running process matches persistence entry — "
                f"full persistence compromise confirmed."
            )
            corroborating = [
                {"domain": "process", "finding": pf}
                for pf in process_findings
                if pf.get("process_name", "").lower() in matched_proc_names
            ]
        else:
            correction_type = UNCONFIRMED
            reason = (
                f"Persistence artifact '{pdata.get('artifact_name', '')}' has no currently "
                f"running flagged process matching its command. "
                f"Persistence may be dormant or the process exited."
            )

        revised_cf = apply_correction(original_cf, correction_type)
        event = CorrectionEvent(
            finding_domain="persistence",
            finding_rule_id=pdata.get("rule_id", "UNKNOWN"),
            correction_type=correction_type,
            original_confidence=original_cf,
            revised_confidence=revised_cf,
            reasoning=reason,
            corroborating_evidence=corroborating,
        )
        events.append(event)
        corrected.append(
            CorrectedFinding(
                source_domain="persistence",
                rule_id=pdata.get("rule_id", "UNKNOWN"),
                severity=severity,
                message=pdata.get("message", ""),
                original_confidence=original_cf,
                revised_confidence=revised_cf,
                correction_type=correction_type,
                correction_reason=reason,
                original_finding=pdata,
                corroborating_evidence=corroborating,
            )
        )

    return corrected, events
