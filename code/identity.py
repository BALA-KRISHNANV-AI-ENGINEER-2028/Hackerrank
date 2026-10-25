"""
Identity resolution module for Ghost Data Still Exists.
Resolves current and historical user identities, aliases, and transitions.
"""
from typing import Dict, List, Optional, Set
import csv


class IdentityResolver:
    def __init__(self, identities_path: str = "dataset/user_identities.csv", audit_log_path: str = "dataset/user_audit_log.csv"):
        self.users: Dict[str, dict] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}
        self.user_history: Dict[str, List[dict]] = {}
        self._load(identities_path, audit_log_path)

    def _load(self, identities_path: str, audit_log_path: str):
        with open(identities_path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                uid = row["user_id"]
                self.users[uid] = row
                email = row["email"].strip().lower()
                if email:
                    self.email_to_uid[email] = uid
                ehash = row["email_hash"].strip().lower()
                if ehash:
                    self.hash_to_uid[ehash] = uid

        with open(audit_log_path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                uid = row["user_id"]
                self.user_history.setdefault(uid, []).append(row)
                if row.get("field_name") == "email":
                    old_e = row.get("old_value", "").strip().lower()
                    new_e = row.get("new_value", "").strip().lower()
                    if old_e:
                        self.email_to_uid[old_e] = uid
                    if new_e:
                        self.email_to_uid[new_e] = uid
                elif row.get("field_name") == "email_hash":
                    old_h = row.get("old_value", "").strip().lower()
                    new_h = row.get("new_value", "").strip().lower()
                    if old_h:
                        self.hash_to_uid[old_h] = uid
                    if new_h:
                        self.hash_to_uid[new_h] = uid

    def resolve(self, request_email: str) -> Optional[dict]:
        email_clean = request_email.strip().lower()
        uid = self.email_to_uid.get(email_clean)
        if not uid and uid not in self.users:
            # Try searching by user_id directly if email is a user_id
            if email_clean in self.users:
                uid = email_clean

        if not uid:
            return None

        user_record = self.users.get(uid, {})
        all_emails: Set[str] = set()
        if user_record.get("email"):
            all_emails.add(user_record["email"].strip().lower())
        all_emails.add(email_clean)

        all_names: Set[str] = set()
        if user_record.get("name"):
            all_names.add(user_record["name"].strip())

        all_phones: Set[str] = set()
        if user_record.get("phone"):
            all_phones.add(user_record["phone"].strip())

        all_hashes: Set[str] = set()
        if user_record.get("email_hash"):
            all_hashes.add(user_record["email_hash"].strip().lower())

        for change in self.user_history.get(uid, []):
            field = change.get("field_name")
            old_val = change.get("old_value", "").strip()
            new_val = change.get("new_value", "").strip()
            if field == "email":
                if old_val:
                    all_emails.add(old_val.lower())
                if new_val:
                    all_emails.add(new_val.lower())
            elif field == "name":
                if old_val:
                    all_names.add(old_val)
                if new_val:
                    all_names.add(new_val)
            elif field == "phone":
                if old_val:
                    all_phones.add(old_val)
                if new_val:
                    all_phones.add(new_val)
            elif field == "email_hash":
                if old_val:
                    all_hashes.add(old_val.lower())
                if new_val:
                    all_hashes.add(new_val.lower())

        return {
            "user_id": uid,
            "primary_email": user_record.get("email", request_email),
            "all_emails": all_emails,
            "all_names": all_names,
            "all_phones": all_phones,
            "all_hashes": all_hashes,
            "current_record": user_record,
            "audit_history": self.user_history.get(uid, [])
        }
