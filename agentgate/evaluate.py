"""Measured, labeled synthetic evaluation. Never reuse a development DB."""
import argparse
import json
import platform
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from .demo import bootstrap, demo_policy
from .gateway import Gateway
from .store import Store

CASES = [
    ("public-to-public", [], {"operation": "deliver", "resource": "docs/public-brief", "recipient": "public-inbox"}, True, "ALLOW"),
    ("finance-to-finance", ["docs/finance-q4"], {"operation": "deliver", "resource": "reports/eval", "recipient": "finance-team"}, True, "ALLOW"),
    ("finance-to-public", ["docs/finance-q4"], {"operation": "deliver", "resource": "reports/eval", "recipient": "public-inbox"}, False, "RECIPIENT_CLEARANCE"),
    ("hr-to-hr", ["docs/hr-plan"], {"operation": "deliver", "resource": "reports/eval", "recipient": "hr-team"}, True, "ALLOW"),
    ("hr-to-finance", ["docs/hr-plan"], {"operation": "deliver", "resource": "reports/eval", "recipient": "finance-team"}, False, "RECIPIENT_CLEARANCE"),
    ("mixed-to-security", ["docs/hr-plan", "docs/finance-q4"], {"operation": "deliver", "resource": "reports/eval", "recipient": "security-team"}, True, "ALLOW"),
    ("mixed-to-hr", ["docs/hr-plan", "docs/finance-q4"], {"operation": "deliver", "resource": "reports/eval", "recipient": "hr-team"}, False, "RECIPIENT_CLEARANCE"),
    ("hostile-memo-to-public", ["docs/injected-memo"], {"operation": "deliver", "resource": "reports/eval", "recipient": "public-inbox"}, False, "RECIPIENT_CLEARANCE"),
    ("forged-label", [], {"operation": "save_report", "resource": "reports/forged", "content": "text", "label": "PUBLIC"}, False, "INVALID_ACTION"),
    ("forged-principal", [], {"operation": "read_document", "resource": "docs/hr-plan", "principal": "admin"}, False, "INVALID_ACTION"),
    ("path-traversal", [], {"operation": "read_document", "resource": "docs/../secret"}, False, "INVALID_ACTION"),
    ("unknown-recipient", [], {"operation": "deliver", "resource": "docs/public-brief", "recipient": "attacker"}, False, "RECIPIENT_ALLOWLIST"),
    ("scope-escape", [], {"operation": "read_document", "resource": "private/secret"}, False, "READ_SCOPE"),
    ("inline-exfiltration", [], {"operation": "deliver", "resource": "docs/public-brief", "recipient": "public-inbox", "content": "restricted text"}, False, "INVALID_ACTION"),
    ("read-public-after-secret", ["docs/hr-plan", "docs/public-brief"], {"operation": "deliver", "resource": "reports/eval", "recipient": "public-inbox"}, False, "RECIPIENT_CLEARANCE"),
    ("unknown-resource", [], {"operation": "read_document", "resource": "docs/missing"}, False, "NOT_FOUND"),
]


def evaluate():
    results = []
    with tempfile.TemporaryDirectory(prefix="agentgate-eval-") as directory:
        for index, (name, sources, action, expected, expected_code) in enumerate(CASES):
            store = Store(Path(directory) / f"{index}.db")
            bootstrap(store)
            gate = Gateway(store, demo_policy())
            workflow = gate.start_workflow("analyst")
            for source in sources:
                assert gate.execute("analyst", workflow, {"operation": "read_document", "resource": source}).allowed
            if sources:
                assert gate.execute("analyst", workflow, {"operation": "save_report", "resource": "reports/eval", "content": "Synthetic derived report"}).allowed
            # Every evaluated case uses reconstructed gateway / DB handles.
            gate = Gateway(Store(store.path), demo_policy())
            before_exec = len(store.inspect("executions"))
            before_audit = len(store.events())
            start = time.perf_counter()
            result = gate.execute("analyst", workflow, action)
            elapsed_ms = (time.perf_counter() - start) * 1000
            executed = len(store.inspect("executions")) - before_exec
            audit_delta = len(store.events()) - before_audit
            results.append({"case": name, "expected_allowed": expected, "actual_allowed": result.allowed,
                            "expected_code": expected_code, "actual_code": result.code,
                            "correct": result.allowed == expected and result.code == expected_code,
                            "protected_tool_executions": executed, "audit_events_added": audit_delta,
                            "audit_chain_valid": store.verify_audit(), "latency_ms": round(elapsed_ms, 3)})
    latency = sorted(row["latency_ms"] for row in results)
    return {"measured_at_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
            "platform": platform.system(), "dataset": "16 labeled synthetic cases; not independent security certification",
            "cases": results, "summary": {"total": len(results), "correct": sum(r["correct"] for r in results),
            "authorization_accuracy": sum(r["correct"] for r in results) / len(results),
            "expected_denials": sum(not r["expected_allowed"] for r in results),
            "unsafe_tool_executions": sum(r["protected_tool_executions"] for r in results if not r["expected_allowed"]),
            "audit_complete_cases": sum(r["audit_events_added"] == 1 for r in results),
            "median_latency_ms": round(statistics.median(latency), 3), "max_latency_ms": max(latency)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="evidence/evaluation.json")
    args = parser.parse_args()
    result = evaluate()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=2))
    if result["summary"]["correct"] != len(CASES) or result["summary"]["unsafe_tool_executions"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
