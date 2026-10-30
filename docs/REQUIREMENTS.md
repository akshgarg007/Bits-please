# PS08 requirements coverage

Source: `PROBLEM_STATEMENT.md`, copied from the organizer repository. No organizer-only datasets or hidden evaluation labels were used.

| Specification requirement | Implementation | Verification |
|---|---|---|
| Three local protected tools | `Gateway._read_document`, `_save_report`, `_deliver` | Authorized workflow + spies on denied tool invocations |
| Identity and operation permissions | Host-bound principal; policy operation allowlist | Unknown identity, workflow ownership and read-only viewer tests |
| Target resource enforcement | Canonical resource identifiers; per-identity namespaces | Traversal, invalid identifier and namespace-boundary tests |
| Recipient authorization | Identity recipient allowlist + recipient clearance | Unknown recipient and insufficient clearance cases |
| Information-flow restrictions | Level maximum + compartment union | Lattice properties, mixed-source tests |
| Trusted policy separate from untrusted content | Policy injected by trusted host; closed proposal schema | Forged policy, label, identity and audit-override fields rejected |
| Preserve restrictions through summaries | Save inherits persistent workflow high-water label | Finance report and second-generation report tests |
| Preserve restrictions through storage / resume | SQLite workflow label + artifact metadata | New Store/Gateway instance tests and restart scenario |
| Classification changes authorized only | No downgrade/declassification interface exposed | Forged labels rejected and artifacts immutable |
| Audit explanation for each decision | Reason code, policy hash, effective label, execution status | Completeness checks, redaction, rollback and tampering tests |
| Streamlit dashboard | Six operator views | AppTest navigation and live interaction tests |
| Block before tool execution | All policy checks precede protected methods | Spies prove protected methods are not invoked |
| Clearly label replay/simulation | UI, CLI and docs disclose deterministic proposals | No prerecorded replay; real gateway executions |
| Optional LLM integration | Not implemented; not required | Deterministic local demo requires no API keys |

## Input and output contract

- Inputs: typed action dictionaries; trusted Pydantic policy; four labeled synthetic documents.
- Resources are logical SQLite IDs, not operating-system paths.
- Outputs: `Decision` objects, immutable report artifacts, local mock inbox records, JSON audit and scenario evidence.
- No exact organizer output schema, mandatory dataset, submission URL or deadline is specified in PS08.
- Labels on fixtures are assigned by the trusted operator. Unknown fields and invalid actions fail closed and generate denial audit events.
- SQLite failures propagate as errors and roll back the transaction; the app never turns them into an authorization success.

## Synthetic data

All figures, staffing information and project names are invented and visibly labeled synthetic. They exist solely to exercise security flows. There is no real personal, financial or confidential organization data.
