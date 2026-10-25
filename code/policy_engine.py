"""
Policy engine module for Ghost Data Still Exists.
Enforces rules defined in dataset/deletion_rules.csv.
"""
from typing import Dict, Optional
import csv


class PolicyEngine:
    def __init__(self, rules_path: str = "dataset/deletion_rules.csv"):
        self.rules: Dict[str, dict] = {}
        with open(rules_path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                self.rules[row["data_category"]] = row

    def get_required_action(self, data_category: str) -> str:
        rule = self.rules.get(data_category)
        if not rule:
            return "DELETE"
        return rule["required_action"]

    def is_retained(self, data_category: str) -> bool:
        return self.get_required_action(data_category) == "RETAIN"

    def requires_anonymization(self, data_category: str) -> bool:
        return self.get_required_action(data_category) == "ANONYMIZE"

    def requires_redaction(self, data_category: str) -> bool:
        return self.get_required_action(data_category) == "REDACT"

    def requires_deletion(self, data_category: str) -> bool:
        return self.get_required_action(data_category) == "DELETE"
