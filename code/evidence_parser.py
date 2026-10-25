"""
Evidence ingestion and normalization module for Ghost Data Still Exists.
Parses SQL dumps, JSON snapshot bundles, structured logs, text handovers, PDFs, and OCR records.
"""
from typing import Dict, List, Optional, Set, Any
import base64
import csv
import glob
import json
import os
import re
import sqlite3
import sys
import zlib


code_dir = os.path.dirname(os.path.abspath(__file__))
if code_dir not in sys.path:
    sys.path.insert(0, code_dir)

try:
    from identity import IdentityResolver
except ImportError:
    from code.identity import IdentityResolver


class Observation:
    def __init__(
        self,
        evidence_id: str,
        captured_at: str,
        system_id: str,
        resource_id: str,
        category: str,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        status: Optional[str] = None, # 'ABSENT', 'PRESENT', 'EXPOSED_PII', 'ANONYMIZED', 'REDACTED', 'ACTIVE', 'DISABLED', 'BLOCKED'
        details: Optional[Dict[str, Any]] = None,
        file_path: Optional[str] = None,
    ):
        self.evidence_id = evidence_id
        self.captured_at = captured_at
        self.system_id = system_id
        self.resource_id = resource_id
        self.category = category
        self.user_id = user_id
        self.email = email.lower() if email else None
        self.phone = phone
        self.status = status
        self.details = details or {}
        self.file_path = file_path

    def __repr__(self):
        return f"<Obs ev={self.evidence_id} sys={self.system_id} res={self.resource_id} status={self.status} email={self.email} uid={self.user_id} cap={self.captured_at}>"


class EvidenceParser:
    def __init__(self, dataset_dir: str = "dataset", resolver: Optional[IdentityResolver] = None):
        self.dataset_dir = dataset_dir
        self.resolver = resolver or IdentityResolver(
            identities_path=os.path.join(dataset_dir, "user_identities.csv"),
            audit_log_path=os.path.join(dataset_dir, "user_audit_log.csv")
        )
        self.manifest: Dict[str, dict] = {}
        self.observations: List[Observation] = []
        self.system_activities: List[dict] = []
        self.resource_to_user: Dict[str, str] = {}
        self.resource_to_emails: Dict[str, Set[str]] = {}
        self._load_manifest()
        self._load_system_activity()
        self._load_all_evidence()

    def _load_manifest(self):
        manifest_path = os.path.join(self.dataset_dir, "evidence_files.csv")
        with open(manifest_path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                self.manifest[row["file_id"]] = row

    def _load_system_activity(self):
        act_path = os.path.join(self.dataset_dir, "system_activity.csv")
        with open(act_path, "r", encoding="utf-8") as f:
            self.system_activities = list(csv.DictReader(f))

        # Index resource links from activity details
        for a in self.system_activities:
            res_id = a.get("resource_id")
            details = a.get("details", "")
            if res_id:
                u_match = re.search(r'\b(user_\d+)\b', details)
                if u_match:
                    self.resource_to_user[res_id] = u_match.group(1)
                e_matches = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', details)
                for em in e_matches:
                    self.resource_to_emails.setdefault(res_id, set()).add(em.lower())

    def _add_obs(self, obs: Observation):
        self.observations.append(obs)
        if obs.resource_id:
            if obs.user_id:
                self.resource_to_user[obs.resource_id] = obs.user_id
            if obs.email:
                self.resource_to_emails.setdefault(obs.resource_id, set()).add(obs.email.lower())

    def _load_all_evidence(self):
        # 1. OCR images
        self._load_image_ocr()
        # 2. PDFs
        self._load_pdfs()
        # 3. Text handover
        self._load_handover_txt()
        # 4. JSON files
        self._load_json_files()
        # 5. SQL databases
        self._load_sql_files()
        # 6. Log files
        self._load_log_files()

    def _load_image_ocr(self):
        ocr_path = os.path.join(self.dataset_dir, "evidence", "extracted_image_ocr.json")
        if not os.path.exists(ocr_path):
            return
        with open(ocr_path, "r", encoding="utf-8") as f:
            ocr_data = json.load(f)

        # Map image filename to file_id
        path_to_fid = {}
        for fid, row in self.manifest.items():
            path_to_fid[os.path.basename(row["file_path"])] = (fid, row["captured_at"], row["file_path"])

        for img_name, text in ocr_data.items():
            if img_name not in path_to_fid:
                continue
            fid, cap_at, full_path = path_to_fid[img_name]
            # Extract user_ids, emails, resource_ids from OCR text
            uids = re.findall(r'\buser_\d+\b', text)
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
            res_ids = re.findall(r'\b(account_\d+|search_\d+|analytics_\d+|support_\d+|export_\d+|data_flow_\d+|backup_\d+|audit_record_\d+|tombstone_\d+)\b', text)
            
            # Map system based on resource_id
            for r in res_ids:
                sys_id = self._system_from_resource(r)
                cat = self._category_from_resource(r)
                uid = uids[0] if uids else None
                em = emails[0] if emails else None
                # Check status
                status = "PRESENT"
                if "tombstone" in r or "Retained reference" in text:
                    status = "REDACTED"
                elif "ANONYMIZED" in text:
                    status = "ANONYMIZED"
                self._add_obs(Observation(
                    evidence_id=fid,
                    captured_at=cap_at,
                    system_id=sys_id,
                    resource_id=r,
                    category=cat,
                    user_id=uid,
                    email=em,
                    status=status,
                    file_path=full_path
                ))

    def _load_pdfs(self):
        pdf_manifest = {fid: row for fid, row in self.manifest.items() if row["file_path"].endswith(".pdf")}
        for fid, row in pdf_manifest.items():
            p = os.path.join(self.dataset_dir, row["file_path"])
            if not os.path.exists(p):
                continue
            with open(p, "rb") as f:
                data = f.read()
            objs = re.findall(rb'(\d+ \d+ obj.*?endobj)', data, re.DOTALL)
            texts = []
            for o in objs:
                if b'ASCII85Decode' in o:
                    s_idx = o.find(b'stream') + 6
                    e_idx = o.find(b'endstream')
                    raw = o[s_idx:e_idx].strip()
                    try:
                        decoded = base64.a85decode(raw, adobe=True)
                        decomp = zlib.decompress(decoded)
                        for m in re.finditer(rb'\((.*?)\)\s*Tj', decomp):
                            texts.append(m.group(1).decode('latin1', 'ignore'))
                    except Exception:
                        pass
            full_txt = " ".join(texts)
            uids = re.findall(r'\buser_\d+\b', full_txt)
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', full_txt)
            res_ids = re.findall(r'\b(account_\d+|search_\d+|analytics_\d+|support_\d+|export_\d+|data_flow_\d+|backup_\d+|audit_record_\d+|tombstone_\d+)\b', full_txt)
            for r in res_ids:
                sys_id = self._system_from_resource(r)
                cat = self._category_from_resource(r)
                # Check if it is a support attachment
                if "delivery_correction_attachment" in row["file_path"] and "support_" in r:
                    cat = "SUPPORT_ATTACHMENT"
                self._add_obs(Observation(
                    evidence_id=fid,
                    captured_at=row["captured_at"],
                    system_id=sys_id,
                    resource_id=r,
                    category=cat,
                    user_id=uids[0] if uids else None,
                    email=emails[0] if emails else None,
                    status="PRESENT",
                    file_path=row["file_path"]
                ))

    def _load_handover_txt(self):
        txt_manifest = {fid: row for fid, row in self.manifest.items() if row["file_path"].endswith(".txt")}
        for fid, row in txt_manifest.items():
            p = os.path.join(self.dataset_dir, row["file_path"])
            if not os.path.exists(p):
                continue
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith("- 2026"):
                        continue
                    parts = [pt.strip() for pt in line[2:].split("|")]
                    if len(parts) >= 6:
                        t_stamp, sys_id, res_id, cat, raw_status, identifier = parts[:6]
                        uid = identifier if identifier.startswith("user_") else None
                        em = identifier if "@" in identifier else None
                        
                        status = "PRESENT"
                        if raw_status in ("NOT_FOUND", "DELETED", "ABSENT"):
                            status = "ABSENT"
                        elif raw_status in ("DISABLED", "STOPPED"):
                            status = "DISABLED"
                        elif raw_status in ("BLOCKED", "RESTORE_BLOCKED"):
                            status = "BLOCKED"
                        elif raw_status in ("ACTIVE", "ENABLED"):
                            status = "ACTIVE"
                        elif raw_status in ("IDENTIFIABLE", "EXPOSED_PII"):
                            status = "EXPOSED_PII"
                        elif raw_status in ("ANONYMIZED", "ANONYMOUS"):
                            status = "ANONYMIZED"
                        elif raw_status in ("REDACTED",):
                            status = "REDACTED"
                        elif raw_status in ("FOUND", "PRESENT"):
                            status = "PRESENT"

                        self._add_obs(Observation(
                            evidence_id=fid,
                            captured_at=row["captured_at"],
                            system_id=sys_id,
                            resource_id=res_id,
                            category=cat,
                            user_id=uid,
                            email=em,
                            status=status,
                            file_path=row["file_path"]
                        ))

    def _load_json_files(self):
        json_manifest = {fid: row for fid, row in self.manifest.items() if row["file_path"].endswith(".json")}
        for fid, row in json_manifest.items():
            p = os.path.join(self.dataset_dir, row["file_path"])
            if not os.path.exists(p):
                continue
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Type 1: service_resource_export
            if "service_exports" in data:
                self._parse_service_resource_export(fid, row["captured_at"], row["file_path"], data["service_exports"])
            # Type 2: customer_data_snapshot_bundle
            elif "snapshots" in data:
                self._parse_snapshot_bundle(fid, row["captured_at"], row["file_path"], data["snapshots"])
            # Type 3: customer_analytics_report
            elif "collection" in data and "records" in data:
                self._parse_collection_records(fid, row["captured_at"], row["file_path"], data["collection"], data["records"])
            # Type 4: general records list
            elif "records" in data:
                orig = data.get("origin", "")
                self._parse_origin_records(fid, row["captured_at"], row["file_path"], orig, data["records"])

    def _parse_service_resource_export(self, fid: str, captured_at: str, path: str, exports: dict):
        # account_service
        accs = exports.get("account_service", {}).get("profile_lookups", [])
        for item in accs:
            res_id = item["resource_id"]
            sc = item.get("status_code", 404)
            prof = item.get("profile")
            status = "ABSENT" if (sc == 404 or prof is None) else "PRESENT"
            em = prof.get("email") if prof else None
            uid = prof.get("customer_reference") if prof else None
            self._add_obs(Observation(fid, captured_at, "account_service", res_id, "USER_PROFILE", uid, em, status=status, file_path=path))

        # analytics_platform
        anas = exports.get("analytics_platform", {}).get("profiles", [])
        for item in anas:
            res_id = item["resource_id"]
            em = item.get("email")
            ph = item.get("phone")
            uid = item.get("customer_reference")
            has_pii = bool(em or ph or uid)
            status = "EXPOSED_PII" if has_pii else "ANONYMIZED"
            self._add_obs(Observation(fid, captured_at, "analytics_platform", res_id, "ANALYTICS_PROFILE", uid, em, ph, status=status, file_path=path))

        # backup_service
        baks = exports.get("backup_service", {}).get("restore_entries", [])
        for item in baks:
            res_id = item["resource_id"]
            uid = item.get("customer_reference")
            em = item.get("customer_email")
            rest_allow = item.get("restore_allowed", False)
            status = "ACTIVE" if rest_allow else "BLOCKED"
            self._add_obs(Observation(fid, captured_at, "backup_service", res_id, "BACKUP_ARCHIVE", uid, em, status=status, file_path=path))

        # export_service
        exps = exports.get("export_service", {}).get("exports", [])
        for item in exps:
            res_id = item["resource_id"]
            em = item.get("owner_email")
            uid = item.get("customer_reference")
            self._add_obs(Observation(fid, captured_at, "export_service", res_id, "USER_EXPORT", uid, em, status="PRESENT", file_path=path))

        # integration_service
        conns = exports.get("integration_service", {}).get("connectors", [])
        for item in conns:
            res_id = item["resource_id"]
            em = item.get("customer_email")
            uid = item.get("customer_reference")
            enabled = item.get("enabled", False)
            status = "ACTIVE" if enabled else "DISABLED"
            self._add_obs(Observation(fid, captured_at, "integration_service", res_id, "DATA_FLOW", uid, em, status=status, file_path=path))

        # search_service
        searches = exports.get("search_service", {}).get("index_queries", [])
        for item in searches:
            res_id = item["resource_id"]
            query = item.get("query", "")
            hits = item.get("hits", {}).get("total", 0)
            docs = item.get("hits", {}).get("documents", [])
            em = query if "@" in query else (docs[0].get("email") if docs else None)
            uid = docs[0].get("customer_reference") if docs else None
            status = "PRESENT" if hits > 0 else "ABSENT"
            self._add_obs(Observation(fid, captured_at, "search_service", res_id, "SEARCH_INDEX_ENTRY", uid, em, status=status, file_path=path))

        # security_service
        audits = exports.get("security_service", {}).get("audit_records", [])
        for item in audits:
            res_id = item["resource_id"]
            uid = item.get("subject_reference")
            self._add_obs(Observation(fid, captured_at, "security_service", res_id, "SECURITY_AUDIT_LOG", uid, None, status="PRESENT", file_path=path))

        # support_platform
        tickets = exports.get("support_platform", {}).get("tickets", [])
        for item in tickets:
            res_id = item["resource_id"]
            em = item.get("requester_email")
            nm = item.get("requester_name")
            ph = item.get("requester_phone")
            uid = item.get("customer_reference")
            has_pii = bool(em or nm or ph)
            status = "EXPOSED_PII" if has_pii else "REDACTED"
            self._add_obs(Observation(fid, captured_at, "support_platform", res_id, "SUPPORT_MESSAGE", uid, em, ph, status=status, file_path=path))

    def _parse_snapshot_bundle(self, fid: str, captured_at: str, path: str, snapshots: list):
        for snap in snapshots:
            d_store = snap.get("data_store", "")
            coll = snap.get("collection", "")
            for rec in snap.get("records", []):
                res_id = rec.get("resource_id")
                if not res_id:
                    continue
                uid = rec.get("customer_reference") or rec.get("user_id") or rec.get("subject_reference")
                em = rec.get("email") or rec.get("requester_email") or rec.get("owner_email") or rec.get("customer_email")
                ph = rec.get("phone") or rec.get("requester_phone")
                
                cat = self._category_from_collection(coll, res_id)
                sys_id = d_store if d_store else self._system_from_resource(res_id)
                status = "PRESENT"
                if "tombstone" in res_id:
                    has_pii = bool(em or ph or rec.get("name") or rec.get("full_name"))
                    status = "EXPOSED_PII" if has_pii else "REDACTED"
                elif "analytics" in res_id:
                    has_pii = bool(em or ph)
                    status = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                elif "support" in res_id and coll == "support_records":
                    has_pii = bool(em or ph or rec.get("requester_name"))
                    status = "EXPOSED_PII" if has_pii else "REDACTED"
                elif "backup" in res_id:
                    rest_allow = rec.get("restore_allowed", True)
                    status = "ACTIVE" if rest_allow else "BLOCKED"
                elif "data_flow" in res_id:
                    enabled = rec.get("enabled", True)
                    status = "ACTIVE" if enabled else "DISABLED"

                self._add_obs(Observation(fid, captured_at, sys_id, res_id, cat, uid, em, ph, status=status, file_path=path))

    def _parse_collection_records(self, fid: str, captured_at: str, path: str, coll: str, records: list):
        for rec in records:
            res_id = rec.get("resource_id")
            if not res_id: continue
            uid = rec.get("customer_reference") or rec.get("user_id") or rec.get("subject_reference")
            em = rec.get("email") or rec.get("owner_email") or rec.get("requester_email") or rec.get("customer_email")
            ph = rec.get("phone") or rec.get("owner_phone") or rec.get("requester_phone")
            
            sys_id = self._system_from_resource(res_id)
            cat = self._category_from_collection(coll, res_id)
            
            status = "PRESENT"
            if sys_id == "analytics_platform":
                has_pii = bool(em or ph or uid)
                status = "EXPOSED_PII" if has_pii else "ANONYMIZED"
            elif sys_id == "support_platform":
                has_pii = bool(em or ph or rec.get("requester_name"))
                status = "EXPOSED_PII" if has_pii else "REDACTED"
            elif sys_id == "backup_service":
                status = "ACTIVE" if rec.get("restore_allowed", False) else "BLOCKED"
            elif sys_id == "integration_service":
                status = "ACTIVE" if rec.get("enabled", False) else "DISABLED"

            self._add_obs(Observation(fid, captured_at, sys_id, res_id, cat, uid, em, ph, status=status, file_path=path))

    def _parse_origin_records(self, fid: str, captured_at: str, path: str, origin: str, records: list):
        for rec in records:
            res_id = rec.get("resource_id")
            if not res_id: continue
            sys_id = self._system_from_resource(res_id)
            cat = self._category_from_resource(res_id)
            uid = rec.get("customer_reference") or rec.get("subject_reference") or rec.get("user_id")
            em = rec.get("email") or rec.get("owner_email") or rec.get("customer_email") or rec.get("requester_email")
            ph = rec.get("phone") or rec.get("owner_phone") or rec.get("requester_phone")
            status = "PRESENT"
            if "backup" in res_id:
                status = "ACTIVE" if rec.get("restore_allowed", False) else "BLOCKED"
            elif "data_flow" in res_id:
                status = "ACTIVE" if rec.get("enabled", False) else "DISABLED"
            self._add_obs(Observation(fid, captured_at, sys_id, res_id, cat, uid, em, ph, status=status, file_path=path))

    def _load_sql_files(self):
        sql_manifest = {fid: row for fid, row in self.manifest.items() if row["file_path"].endswith(".sql")}
        for fid, row in sql_manifest.items():
            p = os.path.join(self.dataset_dir, row["file_path"])
            if not os.path.exists(p):
                continue
            with open(p, "r", encoding="utf-8") as f:
                sql_text = f.read()
            con = sqlite3.connect(":memory:")
            try:
                con.executescript(sql_text)
                tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                for tbl in tables:
                    self._parse_sql_table(fid, row["captured_at"], row["file_path"], con, tbl)
            except Exception:
                pass
            finally:
                con.close()

    def _parse_sql_table(self, fid: str, captured_at: str, path: str, con: sqlite3.Connection, tbl: str):
        cols = [c[1] for c in con.execute(f"PRAGMA table_info({tbl})").fetchall()]
        cur = con.execute(f"SELECT * FROM {tbl}")
        for row in cur.fetchall():
            row_dict = dict(zip(cols, row))
            
            # Check for JSON payload column or any JSON value in the row
            for k, val in list(row_dict.items()):
                if isinstance(val, str) and val.strip().startswith("{") and val.strip().endswith("}"):
                    try:
                        inner = json.loads(val)
                        if isinstance(inner, dict):
                            for ik, iv in inner.items():
                                if ik not in row_dict or row_dict[ik] is None:
                                    row_dict[ik] = iv
                                if ik == "document" and isinstance(iv, dict):
                                    for dk, dv in iv.items():
                                        if dk not in row_dict or row_dict[dk] is None:
                                            row_dict[dk] = dv
                    except Exception:
                        pass

            res_id = row_dict.get("resource_id")
            if not res_id:
                continue
            uid = row_dict.get("customer_reference") or row_dict.get("user_id") or row_dict.get("subject_reference")
            em = row_dict.get("email") or row_dict.get("requester_email") or row_dict.get("owner_email") or row_dict.get("customer_email")
            ph = row_dict.get("phone") or row_dict.get("requester_phone") or row_dict.get("owner_phone")
            
            sys_id = row_dict.get("system_id") or self._system_from_resource(res_id)
            cat = self._category_from_table(tbl, res_id)
            
            status = "PRESENT"
            if "backup" in res_id:
                status = "ACTIVE" if str(row_dict.get("restore_allowed", "0")) in ("1", "true", "True") else "BLOCKED"
            elif "data_flow" in res_id:
                status = "ACTIVE" if str(row_dict.get("enabled", "0")) in ("1", "true", "True") else "DISABLED"
            elif "analytics" in res_id:
                has_pii = bool(em or ph or uid)
                status = "EXPOSED_PII" if has_pii else "ANONYMIZED"
            elif "support" in res_id:
                has_pii = bool(em or ph or row_dict.get("requester_name"))
                status = "EXPOSED_PII" if has_pii else "REDACTED"
            elif "tombstone" in res_id:
                has_pii = bool(em or ph or row_dict.get("full_name") or row_dict.get("name"))
                status = "EXPOSED_PII" if has_pii else "REDACTED"

            self._add_obs(Observation(fid, captured_at, sys_id, res_id, cat, uid, em, ph, status=status, file_path=path))

    def _load_log_files(self):
        log_manifest = {fid: row for fid, row in self.manifest.items() if row["file_path"].endswith(".log")}
        kv_pattern = re.compile(r'([a-zA-Z_]+)=(?:"([^"]*)"|(\S+))')
        for fid, row in log_manifest.items():
            p = os.path.join(self.dataset_dir, row["file_path"])
            if not os.path.exists(p):
                continue
            
            # Two-pass trace correlation
            traces: Dict[str, dict] = {}
            untraced_items: List[dict] = []
            
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    kvs = {}
                    idx = line.find("{")
                    if idx != -1 and line.endswith("}"):
                        try:
                            kvs = json.loads(line[idx:])
                        except Exception:
                            pass
                    if not kvs:
                        for k, v1, v2 in kv_pattern.findall(line):
                            kvs[k] = v1 if v1 else v2
                    
                    if not kvs:
                        continue
                    
                    tr = kvs.get("trace_id")
                    if tr:
                        t = traces.setdefault(tr, {})
                        for k, v in kvs.items():
                            if v is not None and v != "":
                                t[k] = v
                    else:
                        untraced_items.append(kvs)

            # Process all correlated traces
            for tr, d in traces.items():
                res_id = d.get("resource_id")
                if not res_id:
                    continue
                sys_id = d.get("service") or d.get("logger") or self._system_from_resource(res_id)
                if sys_id == "support_replica":
                    sys_id = "support_platform"
                cat = self._category_from_resource(res_id)
                uid = d.get("customer_reference") or d.get("subject_ref") or d.get("subject_reference") or d.get("user_id")
                if not uid:
                    sk = d.get("subject_key") or d.get("lookup_key")
                    if sk and sk.startswith("user_"):
                        uid = sk
                if uid == "null": uid = None
                em = d.get("lookup_key") or d.get("match_key") or d.get("subject_key") or d.get("scan_key") or d.get("owner_key") or d.get("owner_email") or d.get("customer_email") or d.get("email") or d.get("requester_email") or d.get("matched_value")
                corr = d.get("correlation_key")
                if corr:
                    corr_clean = corr.strip().lower()
                    if "@" in corr_clean and not em:
                        em = corr_clean
                    elif corr_clean in self.resolver.hash_to_uid and not uid:
                        uid = self.resolver.hash_to_uid[corr_clean]
                    elif corr_clean in self.resolver.email_to_uid and not uid:
                        uid = self.resolver.email_to_uid[corr_clean]
                if em and "@" not in em:
                    em = None
                
                status = "PRESENT"
                ev_type = d.get("event", "")
                if d.get("http_status") == "404" or d.get("rows") == "0" or "not_found" in ev_type:
                    status = "ABSENT"
                elif "pii_scan" in ev_type or d.get("direct_identifiers", "0") not in ("0", 0, None):
                    status = "EXPOSED_PII"
                elif "anonymized" in ev_type or d.get("audience_cohort"):
                    status = "ANONYMIZED" if not em else "EXPOSED_PII"
                elif "redacted" in ev_type:
                    status = "REDACTED"
                elif "restore" in res_id or "backup" in res_id:
                    rest_val = d.get("restore_allowed") or d.get("deletion_block")
                    if d.get("eligible") == "true" and d.get("deletion_block") == "false":
                        status = "ACTIVE"
                    elif str(d.get("restore_allowed", "")).lower() in ("true", "1"):
                        status = "ACTIVE"
                    elif str(d.get("restore_allowed", "")).lower() in ("false", "0"):
                        status = "BLOCKED"
                elif "data_flow" in res_id:
                    if str(d.get("enabled", "")).lower() in ("true", "1") or d.get("last_delivery_status") == "delivered":
                        status = "ACTIVE"
                    elif str(d.get("enabled", "")).lower() in ("false", "0") or d.get("last_delivery_status") == "stopped":
                        status = "DISABLED"

                self._add_obs(Observation(fid, row["captured_at"], sys_id, res_id, cat, uid, em, status=status, file_path=row["file_path"], details=d))

            for d in untraced_items:
                res_id = d.get("resource_id")
                if not res_id: continue
                sys_id = d.get("service") or d.get("logger") or self._system_from_resource(res_id)
                cat = self._category_from_resource(res_id)
                uid = d.get("customer_reference") or d.get("subject_ref") or d.get("subject_reference") or d.get("user_id")
                if uid == "null": uid = None
                em = d.get("lookup_key") or d.get("match_key") or d.get("email") or d.get("requester_email") or d.get("matched_value")
                if em and "@" not in em: em = None
                status = "PRESENT"
                if d.get("http_status") == "404" or d.get("rows") == "0":
                    status = "ABSENT"
                elif "pii_scan" in d.get("event", ""):
                    status = "EXPOSED_PII"
                self._add_obs(Observation(fid, row["captured_at"], sys_id, res_id, cat, uid, em, status=status, file_path=row["file_path"], details=d))

    def _system_from_resource(self, res_id: str) -> str:
        if res_id.startswith("account_"): return "account_service"
        if res_id.startswith("search_"): return "search_service"
        if res_id.startswith("analytics_"): return "analytics_platform"
        if res_id.startswith("support_"): return "support_platform"
        if res_id.startswith("export_"): return "export_service"
        if res_id.startswith("data_flow_"): return "integration_service"
        if res_id.startswith("backup_"): return "backup_service"
        if res_id.startswith("audit_record_"): return "security_service"
        if res_id.startswith("tombstone_"): return "identity_service"
        return "account_service"

    def _category_from_resource(self, res_id: str) -> str:
        if res_id.startswith("account_"): return "USER_PROFILE"
        if res_id.startswith("search_"): return "SEARCH_INDEX_ENTRY"
        if res_id.startswith("analytics_"): return "ANALYTICS_PROFILE"
        if res_id.startswith("support_"): return "SUPPORT_MESSAGE"
        if res_id.startswith("export_"): return "USER_EXPORT"
        if res_id.startswith("data_flow_"): return "DATA_FLOW"
        if res_id.startswith("backup_"): return "BACKUP_ARCHIVE"
        if res_id.startswith("audit_record_"): return "SECURITY_AUDIT_LOG"
        if res_id.startswith("tombstone_"): return "ACCOUNT_TOMBSTONE"
        return "USER_PROFILE"

    def _category_from_collection(self, coll: str, res_id: str) -> str:
        if coll == "customer_profiles": return "USER_PROFILE"
        if coll == "customer_search_documents": return "SEARCH_INDEX_ENTRY"
        if coll == "customer_analytics_profiles": return "ANALYTICS_PROFILE"
        if coll == "support_records": return "SUPPORT_MESSAGE"
        if coll == "customer_exports": return "USER_EXPORT"
        if coll == "connector_subscriptions": return "DATA_FLOW"
        if coll == "backup_restore_entries": return "BACKUP_ARCHIVE"
        if coll == "security_audit_records": return "SECURITY_AUDIT_LOG"
        return self._category_from_resource(res_id)

    def _category_from_table(self, tbl: str, res_id: str) -> str:
        if "profile" in tbl: return "USER_PROFILE"
        if "search" in tbl: return "SEARCH_INDEX_ENTRY"
        if "analytics" in tbl: return "ANALYTICS_PROFILE"
        if "support" in tbl: return "SUPPORT_MESSAGE"
        if "export" in tbl: return "USER_EXPORT"
        if "connector" in tbl: return "DATA_FLOW"
        if "backup" in tbl: return "BACKUP_ARCHIVE"
        if "audit" in tbl: return "SECURITY_AUDIT_LOG"
        return self._category_from_resource(res_id)
