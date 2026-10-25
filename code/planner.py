"""
Planner module for Ghost Data Still Exists.
Constructs ordered, deterministic remediation and verification plans conforming to challenge specifications.
"""
from typing import Dict, List, Optional, Any


PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

OP_ORDER = {
    # Findings
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    # Remediation
    "DISABLE_DATA_FLOW": 5,
    "BLOCK_RESTORE": 6,
    "DELETE_RECORD": 7,
    "REDACT_RECORD": 8,
    "ANONYMIZE_RECORD": 9,
    # Verification
    "VERIFY_RECORD_ABSENT": 10,
    "VERIFY_RECORD_PRESENT": 11,
    "VERIFY_RECORD_REDACTED": 12,
    "VERIFY_RECORD_ANONYMIZED": 13,
    "VERIFY_DATA_FLOW_DISABLED": 14,
    "VERIFY_RESTORE_BLOCKED": 15,
}


def sort_key_step(step: dict):
    phase = step["phase"]
    op = step["operation"]
    sys_id = step["system_id"]
    res_id = step["resource_id"]
    return (
        PHASE_ORDER.get(phase, 99),
        OP_ORDER.get(op, 99),
        sys_id,
        res_id,
    )


class Planner:
    def __init__(self):
        pass

    def build_plan(
        self,
        status: str,
        findings: List[dict],
        remediations: List[dict],
        verifications: List[dict],
    ) -> List[dict]:
        """
        Builds the ordered JSON steps array according to the challenge rules:
        - NOT_APPLICABLE -> []
        - COMPLETE -> verifications only, with real evidence_id
        - INCOMPLETE -> findings (with real evidence_id), remediations (evidence_id=''), verifications (evidence_id='')
        """
        if status == "NOT_APPLICABLE":
            return []

        raw_steps: List[dict] = []

        if status == "COMPLETE":
            # Verification steps only, preserving their evidence citations
            raw_steps.extend(verifications)
        else:
            # INCOMPLETE
            # 1. Findings (evidence_id preserved)
            raw_steps.extend(findings)
            # 2. Remediation (evidence_id = "")
            for rem in remediations:
                rem_copy = dict(rem)
                rem_copy["evidence_id"] = ""
                raw_steps.append(rem_copy)
            # 3. Future verification (evidence_id = "")
            for ver in verifications:
                ver_copy = dict(ver)
                ver_copy["evidence_id"] = ""
                raw_steps.append(ver_copy)

        # Sort strictly by (phase, operation, system_id, resource_id)
        raw_steps.sort(key=sort_key_step)

        # Re-number consecutively starting at 1
        final_steps: List[dict] = []
        for i, s in enumerate(raw_steps, start=1):
            step_dict = {
                "step_no": i,
                "phase": s["phase"],
                "system_id": s["system_id"],
                "resource_id": s["resource_id"],
                "operation": s["operation"],
                "state": s["state"],
                "evidence_id": s.get("evidence_id", ""),
            }
            final_steps.append(step_dict)

        return final_steps
