# Trust model and security boundaries

## Attacker control

The attacker may control document bodies and the complete action proposal. They may insert fake system messages, pretend management approved delivery, request a public label, supply unsupported fields, invent recipients, use malformed resource paths, or attempt repeated operations.

The attacker cannot control the authenticated host identity, workflow handle binding, policy, initial artifact classification, database, application source, or process memory. This is an in-process reference implementation, not a sandbox for malicious Python code.

## Trusted host contract

1. Authenticate the user outside the planner. Bind their principal to `Gateway.execute`.
2. Create and bind a workflow in the host. Do not expose `start_workflow` as an agent tool.
3. Never reuse model context when starting a clean workflow. Resume the same workflow whenever context is retained.
4. Register only the gateway action entrypoint. The underscore-prefixed protected methods are not an isolation boundary against host code.
5. Route all agent reads, stored outputs and deliveries through the gateway. Keep database inspection, bootstrap, UI controls and export endpoints privileged.
6. Protect policy and SQLite files with operating-system permissions. The demo does not encrypt local storage or implement user authentication.

## Rules

| Check | Effect |
|---|---|
| Closed schema and canonical resource ID | No policy/identity injection, arbitrary paths, inline delivery payloads or unknown operations |
| Workflow ownership | A principal cannot reuse another principal's context |
| Operation allowlist | A read-only viewer cannot save or deliver |
| Resource namespaces | `docs-evil/x` does not match the `docs` scope |
| Actor clearance | Reads and continued use require sufficient sensitivity and compartments |
| Persistent join | All read sources contribute to derived report restrictions and provenance |
| Recipient allowlist and dominance | Delivery requires permitted recipient, adequate level and all compartments |
| Immutable artifacts | A saved restricted artifact cannot be overwritten with a public replacement |
| No declassification action | Neither a document nor a proposal may lower classification |
| Atomic transaction | Audit failure rolls back local state and side effects |

## Deliberate conservative behavior

After a restricted read, even delivery of a public artifact is governed by the workflow high-water label. This prevents an agent from encoding sensitive information through a later lower-classified action. It can block harmless work; a host may begin a genuinely clean context for independent public tasks.

Provenance includes every document/report read in the workflow, including sources that may not have contributed to a particular summary. This favors traceable overclassification over uncertain model-based attribution.

## Out of scope / future engineering

- Arbitrary host code execution, a compromised operator, direct SQLite editing or malicious policy provisioning.
- Untracked human copy/paste between contexts; timing/covert channels; side channels in denied-action metadata.
- Production authentication, per-user UI visibility, encryption at rest, multi-tenant access, quotas and remote APIs.
- General detection of prompt injection, prevention of all sensitive text in user-written content, or semantic correctness of summaries.
- Nonlocal side effects: email/network delivery needs a transactional outbox, independent worker and provider idempotency. SQLite rollback cannot undo a sent email.
- Audit administrator resistance: use external checkpoints or an append-only service. The current internal hash chain cannot detect total history replacement or tail truncation without an external checkpoint.
- Schema migrations, high-volume retention, policy approval workflows and authorized declassification.

An optional LLM can generate the same action schema, but it receives no policy authority. This submission deliberately needs no network/model availability during the demo.
