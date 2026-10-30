"""Authorize before calling a protected tool. One transaction per decision."""
import json
import uuid
from pydantic import ValidationError
from .models import Action, Decision, Label, Policy
from .store import Store, canonical, digest


class Denied(Exception):
    def __init__(self, code, reason):
        self.code, self.reason = code, reason


def require(condition, code, reason):
    if not condition:
        raise Denied(code, reason)


def within(resource, scopes):
    return any(resource.startswith(scope + "/") for scope in scopes)


def normalized_policy(value):
    """Policy collection order has no semantic meaning; hash it consistently."""
    if isinstance(value, dict):
        return {key: normalized_policy(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted(normalized_policy(item) for item in value)
    return value


class Gateway:
    def __init__(self, store: Store, policy: Policy):
        self.store = store
        # Isolate from subsequent mutation of the caller's policy dictionaries.
        self.policy = Policy.model_validate_json(policy.model_dump_json())
        self.policy_hash = digest(canonical(normalized_policy(self.policy.model_dump(mode="json"))))

    def start_workflow(self, principal):
        if principal not in self.policy.principals:
            raise ValueError("Unknown authenticated principal")
        workflow = str(uuid.uuid4())
        with self.store.connection() as db:
            db.execute("INSERT INTO workflows VALUES(?,?,?,?)",
                       (workflow, principal, canonical(Label().as_dict()), "[]"))
        return workflow

    def execute(self, principal: str, workflow: str, proposal: dict) -> Decision:
        """principal comes from the trusted host, NEVER from the proposal.

        Workflow IDs are host-owned handles; a planner cannot start/switch them.
        A fresh workflow must have a fresh model context (see threat model).
        """
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            action = None
            effective = None
            data = None
            try:
                try:
                    action = Action.model_validate(proposal)
                except ValidationError:
                    raise Denied("INVALID_ACTION", "Action does not match the closed tool schema.")
                actor = self.policy.principals.get(principal)
                require(actor is not None, "UNKNOWN_IDENTITY", "Identity is not in trusted policy.")
                state = db.execute("SELECT * FROM workflows WHERE id=?", (workflow,)).fetchone()
                require(state is not None, "UNKNOWN_WORKFLOW", "Workflow does not exist.")
                require(state["principal"] == principal, "WORKFLOW_OWNER", "Workflow belongs to another identity.")
                require(action.operation in actor.operations, "OPERATION_DENIED", "Identity lacks this operation permission.")
                context_label = Label.model_validate_json(state["label"])
                sources = set(json.loads(state["sources"]))
                if action.operation == "save_report":
                    require(within(action.resource, actor.write_scopes), "WRITE_SCOPE", "Target is outside permitted report namespaces.")
                    require(not db.execute("SELECT 1 FROM artifacts WHERE id=?", (action.resource,)).fetchone(),
                            "IMMUTABLE_ARTIFACT", "Artifacts are immutable; choose a new report ID.")
                    effective = context_label
                    require(actor.clearance.dominates(effective), "ACTOR_CLEARANCE", "Current identity cannot use this workflow classification.")
                    data = self._save_report(db, action, effective, sources)
                else:
                    require(within(action.resource, actor.read_scopes), "READ_SCOPE", "Resource is outside permitted namespaces.")
                    artifact = db.execute("SELECT * FROM artifacts WHERE id=?", (action.resource,)).fetchone()
                    require(artifact is not None, "NOT_FOUND", "Resource does not exist in the permitted namespace.")
                    require(digest(artifact["content"]) == artifact["content_hash"], "ARTIFACT_INTEGRITY", "Stored content fingerprint does not match.")
                    label = Label.model_validate_json(artifact["label"])
                    effective = context_label.join(label)
                    require(actor.clearance.dominates(effective), "ACTOR_CLEARANCE", "Identity lacks the required clearance or compartments.")
                    if action.operation == "read_document":
                        data = self._read_document(db, artifact)
                        sources.add(action.resource)
                        db.execute("UPDATE workflows SET label=?,sources=? WHERE id=?",
                                   (canonical(effective.as_dict()), canonical(sorted(sources)), workflow))
                    else:
                        require(action.recipient in actor.recipients, "RECIPIENT_ALLOWLIST", "Identity cannot deliver to this recipient.")
                        recipient = self.policy.recipients.get(action.recipient)
                        require(recipient is not None, "UNKNOWN_RECIPIENT", "Recipient is absent from trusted policy.")
                        require(recipient.dominates(effective), "RECIPIENT_CLEARANCE", "Recipient cannot receive the effective level and compartments.")
                        require(not db.execute("SELECT 1 FROM inbox WHERE recipient=? AND artifact=? AND workflow=?",
                                               (action.recipient, action.resource, workflow)).fetchone(),
                                "DUPLICATE_DELIVERY", "This immutable artifact was already delivered in this workflow.")
                        data = self._deliver(db, action, artifact, workflow)
                db.execute("INSERT INTO executions(operation,resource,workflow) VALUES(?,?,?)",
                           (action.operation, action.resource, workflow))
                allowed, code, reason = True, "ALLOW", "Identity, operation, resource and information-flow checks passed."
            except Denied as error:
                allowed, code, reason = False, error.code, error.reason
            # No proposal content, document text or validation input is written to audit.
            event_id = self.store.audit(db, {
                "principal": principal, "workflow": workflow, "policy_version": self.policy.version,
                "policy_hash": self.policy_hash, "operation": action.operation if action else "invalid",
                "resource": action.resource if action else None, "recipient": action.recipient if action else None,
                "allowed": allowed, "code": code, "reason": reason,
                "effective_label": effective.as_dict() if effective else None,
                "executed": allowed,
            })
            return Decision(allowed=allowed, code=code, reason=reason, event_id=event_id,
                            effective_label=effective.as_dict() if effective else None, data=data)

    # These tools are host-private. Never register them directly with an agent.
    @staticmethod
    def _read_document(db, artifact):
        return {"content": artifact["content"], "resource": artifact["id"],
                "label": json.loads(artifact["label"]), "parents": json.loads(artifact["parents"])}

    @staticmethod
    def _save_report(db, action, label, sources):
        db.execute("INSERT INTO artifacts VALUES(?,?,?,?,?,?)",
                   (action.resource, action.content, canonical(label.as_dict()),
                    canonical(sorted(sources)), digest(action.content), "report"))
        return {"resource": action.resource, "label": label.as_dict(), "parents": sorted(sources)}

    @staticmethod
    def _deliver(db, action, artifact, workflow):
        cursor = db.execute("INSERT INTO inbox(recipient,artifact,workflow,content_hash) VALUES(?,?,?,?)",
                            (action.recipient, action.resource, workflow, artifact["content_hash"]))
        return {"delivery_id": cursor.lastrowid, "recipient": action.recipient, "resource": action.resource}
