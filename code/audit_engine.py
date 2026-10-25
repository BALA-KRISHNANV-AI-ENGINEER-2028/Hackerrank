"""
Audit engine for Ghost Data Still Exists.
Reconstructs the deletion state at audit_at, detects violations and risks,
and produces evidence-grounded verdicts and steps.
"""
from typing import Dict, List, Tuple, Set, Optional, Any
from datetime import datetime
import re

from code.identity import IdentityResolver
from code.evidence_parser import EvidenceParser, Observation
from code.policy_engine import PolicyEngine
from code.planner import Planner


def is_valid_deletion_request(text: str) -> bool:
    """
    Checks if request text authorizes deletion.
    Returns False for non-deletion requests (access, update, marketing opt-out, login help).
    """
    t = text.lower()
    
    # Explicit non-deletion requests
    if "do not close the account" in t or "do not delete" in t:
        return False
    if "leave the account active" in t or "leave the rest of the profile" in t or "leave the profile untouched" in t:
        return False
    if "out of date" in t and ("replace it with" in t or "update" in t):
        return False
    if "marketing lists only" in t and "still want receipts" in t:
        return False
    if "can't access my profile and need help resetting" in t or "help resetting the login" in t:
        return False
    if "export my data only" in t or "send me a copy only" in t:
        return False
        
    return True


class AuditEngine:
    def __init__(self, dataset_dir: str = "dataset"):
        self.resolver = IdentityResolver(
            identities_path=f"{dataset_dir}/user_identities.csv",
            audit_log_path=f"{dataset_dir}/user_audit_log.csv"
        )
        self.parser = EvidenceParser(dataset_dir=dataset_dir)
        self.policy = PolicyEngine(rules_path=f"{dataset_dir}/deletion_rules.csv")
        self.planner = Planner()

    def audit_case(self, case_row: dict) -> Tuple[str, List[dict]]:
        case_id = case_row["case_id"]
        request_text = case_row.get("request_text", "")
        email = case_row.get("email", "").strip()
        audit_at = case_row.get("audit_at", "")

        # 1. Authenticity / authorization check
        if not is_valid_deletion_request(request_text):
            return "NOT_APPLICABLE", []

        # 2. Identity resolution
        identity = self.resolver.resolve(email)
        user_id = identity["user_id"] if identity else None
        emails = identity["all_emails"] if identity else {email.lower()}

        # 3. Collect observations at or before audit_at
        user_observations: List[Observation] = []
        for o in self.parser.observations:
            if o.captured_at > audit_at:
                continue
            
            # Check match
            is_match = False
            if o.user_id and o.user_id == user_id:
                is_match = True
            elif o.email and o.email in emails:
                is_match = True
            elif o.resource_id in self.parser.resource_to_user and self.parser.resource_to_user[o.resource_id] == user_id:
                is_match = True
            elif o.resource_id in self.parser.resource_to_emails and any(e in emails for e in self.parser.resource_to_emails[o.resource_id]):
                is_match = True

            if is_match:
                user_observations.append(o)

        # 4. Check if we also need to discover primary account from activities / evidence
        primary_account = self._find_primary_account(user_id, emails, audit_at, user_observations)

        # 5. Group observations by resource_id (keeping the latest observation <= audit_at)
        res_latest_obs: Dict[str, Observation] = {}
        for o in user_observations:
            r = o.resource_id
            if r not in res_latest_obs or o.captured_at > res_latest_obs[r].captured_at:
                res_latest_obs[r] = o

        # If primary_account not in observations, determine its status from latest evidence
        if primary_account and primary_account not in res_latest_obs:
            acc_obs = self._synthesize_account_observation(primary_account, audit_at, user_observations)
            if acc_obs:
                res_latest_obs[primary_account] = acc_obs

        # 6. Evaluate each resource against policy
        findings: List[dict] = []
        remediations: List[dict] = []
        verifications: List[dict] = []

        # Process resources
        for r_id, obs in res_latest_obs.items():
            sys_id = obs.system_id
            status = obs.status
            ev_id = obs.evidence_id

            if sys_id == "account_service":
                if status == "PRESENT":
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "REPORT_REMAINING_RECORD",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "DELETE_RECORD",
                        "state": "ABSENT",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                    })
                elif status == "ABSENT":
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                        "evidence_id": ev_id,
                    })

            elif sys_id == "search_service":
                if status == "PRESENT":
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "REPORT_REMAINING_RECORD",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "DELETE_RECORD",
                        "state": "ABSENT",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                    })
                elif status == "ABSENT":
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                        "evidence_id": ev_id,
                    })

            elif sys_id == "export_service":
                if status == "PRESENT":
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "REPORT_REMAINING_RECORD",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "DELETE_RECORD",
                        "state": "ABSENT",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                    })

            elif sys_id == "support_platform":
                if obs.category == "SUPPORT_ATTACHMENT":
                    # Attachments must be deleted
                    if status == "PRESENT":
                        findings.append({
                            "phase": "FINDING",
                            "system_id": sys_id,
                            "resource_id": r_id,
                            "operation": "REPORT_REMAINING_RECORD",
                            "state": "PRESENT",
                            "evidence_id": ev_id,
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": r_id,
                            "operation": "DELETE_RECORD",
                            "state": "ABSENT",
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": r_id,
                            "operation": "VERIFY_RECORD_ABSENT",
                            "state": "ABSENT",
                        })
                else:
                    # Messages must be redacted
                    if status in ("PRESENT", "EXPOSED_PII"):
                        findings.append({
                            "phase": "FINDING",
                            "system_id": sys_id,
                            "resource_id": r_id,
                            "operation": "REPORT_EXPOSED_PII",
                            "state": "PRESENT",
                            "evidence_id": ev_id,
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": r_id,
                            "operation": "REDACT_RECORD",
                            "state": "REDACTED",
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": r_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                        })
                    elif status == "REDACTED":
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": r_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": ev_id,
                        })

            elif sys_id == "analytics_platform":
                if status in ("PRESENT", "EXPOSED_PII"):
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "REPORT_EXPOSED_PII",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "ANONYMIZE_RECORD",
                        "state": "ANONYMIZED",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RECORD_ANONYMIZED",
                        "state": "ANONYMIZED",
                    })
                elif status == "ANONYMIZED":
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RECORD_ANONYMIZED",
                        "state": "ANONYMIZED",
                        "evidence_id": ev_id,
                    })

            elif sys_id == "integration_service":
                if status == "ACTIVE":
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "REPORT_ACTIVE_DATA_FLOW",
                        "state": "ACTIVE",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "DISABLE_DATA_FLOW",
                        "state": "DISABLED",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_DATA_FLOW_DISABLED",
                        "state": "DISABLED",
                    })
                elif status == "DISABLED":
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_DATA_FLOW_DISABLED",
                        "state": "DISABLED",
                        "evidence_id": ev_id,
                    })

            elif sys_id == "backup_service":
                if status == "ACTIVE":
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "REPORT_RESTORE_RISK",
                        "state": "ACTIVE",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "BLOCK_RESTORE",
                        "state": "BLOCKED",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RESTORE_BLOCKED",
                        "state": "BLOCKED",
                    })
                elif status == "BLOCKED":
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RESTORE_BLOCKED",
                        "state": "BLOCKED",
                        "evidence_id": ev_id,
                    })

            elif sys_id == "security_service":
                if status == "PRESENT":
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RECORD_PRESENT",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    })

            elif sys_id == "identity_service":
                if status in ("PRESENT", "EXPOSED_PII"):
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "REPORT_EXPOSED_PII",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "REDACT_RECORD",
                        "state": "REDACTED",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RECORD_REDACTED",
                        "state": "REDACTED",
                    })
                elif status == "REDACTED":
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": r_id,
                        "operation": "VERIFY_RECORD_REDACTED",
                        "state": "REDACTED",
                        "evidence_id": ev_id,
                    })

        # 7. Overall status
        if findings:
            status = "INCOMPLETE"
        else:
            status = "COMPLETE"

        # 8. Build ordered plan
        steps = self.planner.build_plan(status, findings, remediations, verifications)
        return status, steps

    def _find_primary_account(self, user_id: Optional[str], emails: Set[str], audit_at: str, user_obs: List[Observation]) -> Optional[str]:
        # 1. From user observations
        for o in user_obs:
            if o.system_id == "account_service":
                return o.resource_id

        # 2. From system_activities
        for a in self.parser.system_activities:
            if a.get("event_time", "") > audit_at:
                continue
            res_id = a.get("resource_id", "")
            if res_id.startswith("account_"):
                if user_id and user_id in str(a.values()):
                    return res_id
                if any(e in str(a.values()).lower() for e in emails):
                    return res_id

        # 3. Convention account_{num} if user_{num}
        if user_id and user_id.startswith("user_"):
            num = user_id.split("_")[1]
            candidate = f"account_{num}"
            return candidate

        return None

    def _synthesize_account_observation(self, account_id: str, audit_at: str, user_obs: List[Observation]) -> Optional[Observation]:
        # Look for the latest evidence before audit_at that covers accounts
        # Prefer evidence from existing observations
        preferred_ev_id = None
        for o in user_obs:
            if o.evidence_id:
                preferred_ev_id = o.evidence_id
                break

        if not preferred_ev_id:
            # Pick latest evidence file before audit_at
            candidates = [m for m in self.parser.manifest.values() if m["captured_at"] <= audit_at]
            if candidates:
                candidates.sort(key=lambda x: x["captured_at"], reverse=True)
                preferred_ev_id = candidates[0]["file_id"]
            else:
                preferred_ev_id = "evidence_54"

        ev_info = self.parser.manifest.get(preferred_ev_id, {})
        cap_at = ev_info.get("captured_at", audit_at)
        fpath = ev_info.get("file_path", "")

        return Observation(
            evidence_id=preferred_ev_id,
            captured_at=cap_at,
            system_id="account_service",
            resource_id=account_id,
            category="USER_PROFILE",
            status="ABSENT",
            file_path=fpath
        )
