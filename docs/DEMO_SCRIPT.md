# Three-minute demo

## 0:00–0:25 — The problem

“Agents read untrusted text and then act. A malicious document can ask for a secret to be sent outside the organization. Asking the model to be careful is not an authorization boundary. AGENTGATE puts a deterministic permission check between the proposal and the tool.”

Show Overview. Explain that all records are synthetic and the proposal generator is deterministic; the gateway and SQLite executions are live.

## 0:25–0:55 — Prove legitimate work still works

Open Live scenarios → Authorized finance workflow → Run. Show all three ALLOW decisions. Open Artifacts & inbox: the report inherits CONFIDENTIAL + FINANCE and points back to its source. One mock delivery exists for finance.

## 0:55–1:35 — Attack the boundary

Run Prompt injection & forged classification. Explain that the memo claims “SYSTEM OVERRIDE” and requests PUBLIC reclassification and public delivery. The forged label fails the closed schema. Saving a normal summary succeeds but keeps the source restrictions. Public delivery fails recipient clearance. The action is audited and the delivery tool is never called.

## 1:35–2:05 — Prove persistence

Run Restrictions after restart. This reconstructs both the gateway and SQLite connection. Public delivery still fails; the HR team succeeds. The restriction is stored metadata, not a reminder in a prompt.

## 2:05–2:35 — Show the distinguishing feature

Run Mixed-source information flow. Finance + HR produces RESTRICTED with both compartments. Finance-only and HR-only access are insufficient; the security team is authorized for both. Explain why summarization cannot silently downgrade a document.

## 2:35–3:00 — Close with evidence

Open Audit explorer and an individual denial. Show policy fingerprint, effective label, reason and `executed: false`. Show the evaluation JSON and pytest output. Say precisely what was measured, and acknowledge the trusted-host/local-demo boundary.

“Our contribution is enforceable information flow across tool calls and resumed workflows, with evidence for each decision.”

## Likely questions

**Does this detect every prompt injection?** No. It does not need to detect malicious prose to reject an unauthorized action. It enforces the declared policy independently.

**Where is the AI?** An LLM is optional in PS08. We use deterministic proposals to make the security behavior repeatable and offline. An LLM can submit the same schema without obtaining authority.

**Can someone call the tool directly?** Not through the planner interface. Host code and the database are trusted in this prototype; arbitrary code execution in that host bypasses an in-process library.

**Can the model make a new clean workflow?** No workflow-creation tool is registered for it. The host must bind context and workflow together. The UI exposes creation only as a trusted operator control.

**What is the tradeoff?** Conservative overclassification. After reading restricted data, a harmless summary may still be restricted. We prefer an explicit authorized release process over trusting a model to prove a summary contains no sensitive information.

**Can the audit be forged?** Ordinary edits break the hash chain. An administrator who rewrites the entire chain can evade this; production needs external checkpoints.

**Is this production-ready?** No. Authentication, hardened isolation, external delivery, encryption and independent security assessment remain future work.
