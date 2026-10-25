#!/usr/bin/env python3
"""
Phase-0 Dataset Profiler for Ghost Data Still Exists (GhostTrace).
Read-only inspection tool for dataset files, schemas, evidence formats,
temporal bounds, and sample ground truth structure.
"""
import csv
import glob
import json
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime


def inspect_csv(path: str):
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        try:
            headers = next(reader)
        except StopIteration:
            return {"error": "Empty file", "rows": 0}
        
        row_count = 0
        non_empty_counts = [0] * len(headers)
        samples = []
        for row in reader:
            row_count += 1
            if row_count <= 3:
                samples.append(dict(zip(headers, row)))
            for i, val in enumerate(row):
                if i < len(non_empty_counts) and val.strip():
                    non_empty_counts[i] += 1

    return {
        "file": os.path.basename(path),
        "path": path,
        "rows": row_count,
        "columns": headers,
        "field_fill_rates": {headers[i]: f"{(non_empty_counts[i]/row_count*100):.1f}%" if row_count else "0%" for i in range(len(headers))},
        "sample": samples[:2]
    }


def profile():
    base_dir = "dataset"
    print("=" * 80)
    print("PHASE-0 DATASET PROFILER: Ghost Data Still Exists")
    print(f"Base Directory: {os.path.abspath(base_dir)}")
    print("=" * 80)

    # 1. Profile CSV Schemas
    csv_files = [
        "deletion_requests.csv",
        "sample_deletion_requests.csv",
        "sample_output.csv",
        "user_identities.csv",
        "user_audit_log.csv",
        "system_activity.csv",
        "deletion_rules.csv",
        "evidence_files.csv",
    ]

    print("\n--- 1. CSV FILES & SCHEMAS ---")
    profiles = {}
    for fname in csv_files:
        fpath = os.path.join(base_dir, fname)
        p = inspect_csv(fpath)
        profiles[fname] = p
        print(f"\n[{fname}] - {p.get('rows', 0)} rows")
        print(f"  Columns: {p.get('columns', [])}")
        print(f"  Fill Rates: {p.get('field_fill_rates', {})}")

    # 2. Deletion Requests Analysis
    print("\n--- 2. DELETION REQUESTS PROFILE (518 cases) ---")
    with open(os.path.join(base_dir, "deletion_requests.csv"), "r") as f:
        del_reqs = list(csv.DictReader(f))

    req_statuses = Counter(r["reported_status"] for r in del_reqs)
    print(f"Reported status distribution (Claims): {dict(req_statuses)}")
    
    # Check temporal ordering in requests
    req_at = [r["requested_at"] for r in del_reqs if r["requested_at"]]
    rep_at = [r["reported_at"] for r in del_reqs if r["reported_at"]]
    aud_at = [r["audit_at"] for r in del_reqs if r["audit_at"]]
    print(f"Time Bounds: requested_at [{min(req_at)} to {max(req_at)}]")
    print(f"Time Bounds: reported_at  [{min(rep_at)} to {max(rep_at)}]")
    print(f"Time Bounds: audit_at     [{min(aud_at)} to {max(aud_at)}]")

    # 3. Sample Output Ground Truth Analysis (32 cases)
    print("\n--- 3. SAMPLE GROUND TRUTH ANALYSIS (sample_output.csv) ---")
    with open(os.path.join(base_dir, "sample_output.csv"), "r") as f:
        samples = list(csv.DictReader(f))

    status_dist = Counter(s["deletion_status"] for s in samples)
    print(f"Ground Truth Statuses: {dict(status_dist)}")

    phase_counter = Counter()
    op_counter = Counter()
    sys_counter = Counter()
    evidence_counter = Counter()

    for s in samples:
        steps = json.loads(s["steps_json"])
        for st in steps:
            phase_counter[st["phase"]] += 1
            op_counter[st["operation"]] += 1
            sys_counter[st["system_id"]] += 1
            if st.get("evidence_id"):
                evidence_counter[st["evidence_id"]] += 1

    print(f"Phases present in sample ground truth: {dict(phase_counter)}")
    print(f"Operations in sample ground truth: {dict(op_counter)}")
    print(f"Systems referenced in sample ground truth: {dict(sys_counter)}")
    print(f"Distinct Evidence IDs cited in samples: {len(evidence_counter)} (Total citations: {sum(evidence_counter.values())})")

    # 4. Evidence Manifest vs Filesystem Audit
    print("\n--- 4. EVIDENCE MANIFEST AUDIT (evidence_files.csv) ---")
    with open(os.path.join(base_dir, "evidence_files.csv"), "r") as f:
        manifest_rows = list(csv.DictReader(f))

    manifest_origins = Counter(r["origin"] for r in manifest_rows)
    print(f"Total entries in manifest: {len(manifest_rows)}")
    print(f"Origins ({len(manifest_origins)}): {dict(manifest_origins)}")

    existing_files = 0
    missing_files = []
    file_types = Counter()
    for row in manifest_rows:
        rel_path = row["file_path"]
        full_path = os.path.join(base_dir, rel_path)
        ext = os.path.splitext(rel_path)[1]
        file_types[ext] += 1
        if os.path.exists(full_path):
            existing_files += 1
        else:
            missing_files.append((row["file_id"], rel_path))

    print(f"File extensions in manifest: {dict(file_types)}")
    print(f"Files existing on disk: {existing_files}/{len(manifest_rows)}")
    print(f"Files missing from disk: {len(missing_files)}/{len(manifest_rows)}")
    if missing_files:
        print("Sample missing files:")
        for fid, path in missing_files[:5]:
            print(f"  - {fid}: {path}")

    # 5. SQL Databases Profiling
    print("\n--- 5. SQL DATABASE EXPORTS AUDIT ---")
    sql_files = glob.glob(os.path.join(base_dir, "evidence/databases/*.sql"))
    print(f"Found {len(sql_files)} SQL files on disk.")
    sql_tables = Counter()
    for sf in sql_files[:5]:
        with open(sf, "r", encoding="utf-8") as f:
            content = f.read()
        con = sqlite3.connect(":memory:")
        try:
            con.executescript(content)
            tbls = [t[0] for t in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            for t in tbls:
                sql_tables[t] += 1
        except Exception as e:
            print(f"  Error inspecting {os.path.basename(sf)}: {e}")
        finally:
            con.close()
    print(f"Common table names found across SQL dumps: {dict(sql_tables)}")

    # 6. Deletion Rules Profile
    print("\n--- 6. DELETION RULES AUDIT (deletion_rules.csv) ---")
    with open(os.path.join(base_dir, "deletion_rules.csv"), "r") as f:
        rules = list(csv.DictReader(f))
    print(f"Loaded {len(rules)} policy rules:")
    for r in rules:
        print(f"  - [{r['data_category']}] (condition: {r['condition']}) -> {r['required_action']}")

    # 7. System Activity Profiling
    print("\n--- 7. SYSTEM ACTIVITY AUDIT (system_activity.csv) ---")
    with open(os.path.join(base_dir, "system_activity.csv"), "r") as f:
        activities = list(csv.DictReader(f))
    act_types = Counter(a["event_type"] for a in activities)
    act_results = Counter(a["reported_result"] for a in activities)
    print(f"Total activity events: {len(activities)}")
    print(f"Event types: {dict(act_types)}")
    print(f"Reported results: {dict(act_results)}")

    print("\n" + "=" * 80)
    print("PHASE-0 PROFILING COMPLETE.")
    print("=" * 80)


if __name__ == "__main__":
    profile()
