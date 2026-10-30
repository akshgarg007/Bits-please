import argparse
import json
from .store import Store
from .demo import bootstrap, run_scenario


def main():
    parser = argparse.ArgumentParser(description="Run AGENTGATE live deterministic demonstrations")
    parser.add_argument("--db", default="data/agentgate.db")
    parser.add_argument("--scenario", choices=["all", "authorized", "injection", "resume", "compartments"], default="all")
    args = parser.parse_args()
    store = Store(args.db)
    bootstrap(store)
    scenarios = ["authorized", "injection", "resume", "compartments"] if args.scenario == "all" else [args.scenario]
    results = [run_scenario(store, scenario) for scenario in scenarios]
    print(json.dumps({"mode": "live deterministic proposals (not LLM or replay)", "scenarios": results,
                      "audit_chain_valid": store.verify_audit(), "delivery_count": len(store.inspect("inbox"))}, indent=2))


if __name__ == "__main__":
    main()
