#!/usr/bin/env python3
"""
Main entry point for Ghost Data Still Exists deletion audit agent.
Processes all 518 cases from dataset/deletion_requests.csv and writes output.csv.
"""
import csv
import json
import sys
import os
import time

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
code_dir = os.path.dirname(os.path.abspath(__file__))
for p in [code_dir, repo_root]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from audit_engine import AuditEngine
except ImportError:
    from code.audit_engine import AuditEngine


def run_audit(dataset_dir: str = "dataset", output_path: str = "output.csv"):
    start_time = time.time()
    print(f"Initializing Ghost Data Still Exists Audit Engine (dataset={dataset_dir})...")
    engine = AuditEngine(dataset_dir=dataset_dir)

    requests_file = os.path.join(dataset_dir, "deletion_requests.csv")
    if not os.path.exists(requests_file):
        print(f"Error: Could not find requests file at {requests_file}")
        sys.exit(1)

    print(f"Reading requests from {requests_file}...")
    with open(requests_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        requests = list(reader)

    total_cases = len(requests)
    print(f"Loaded {total_cases} deletion audit cases.")

    def case_sort_key(item):
        cid = item["case_id"]
        parts = cid.split("_")
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else cid

    # Sort requests naturally by numeric case_id
    requests.sort(key=case_sort_key)

    results = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}
    total_steps = 0

    print("Auditing cases...")
    for idx, case in enumerate(requests, start=1):
        case_id = case["case_id"]
        status, steps = engine.audit_case(case)
        status_counts[status] = status_counts.get(status, 0) + 1
        total_steps += len(steps)

        # Ensure steps are serialized cleanly as compact JSON
        steps_json = json.dumps(steps, separators=(',', ':'))
        results.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": steps_json
        })

        if idx % 100 == 0 or idx == total_cases:
            print(f"  Processed {idx}/{total_cases} cases ({idx*100//total_cases}%)")

    # Sort results strictly by natural case_id
    results.sort(key=case_sort_key)

    print(f"Writing {len(results)} rows to {output_path}...")
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(results)

    elapsed = time.time() - start_time
    print("=" * 60)
    print(f"Audit completed in {elapsed:.2f} seconds.")
    print(f"Output saved to: {output_path}")
    print(f"Total cases: {total_cases}")
    print(f"Status distribution: {status_counts}")
    print(f"Total steps generated: {total_steps} (avg {total_steps/total_cases:.1f}/case)")
    print("=" * 60)


if __name__ == "__main__":
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else "dataset"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "output.csv"
    run_audit(dataset_dir=dataset_path, output_path=out_path)
