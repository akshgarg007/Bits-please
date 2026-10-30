import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import pytest
from agentgate.demo import bootstrap, demo_policy, run_scenario
from agentgate.gateway import Gateway
from agentgate.models import Label
from agentgate.store import Store


@pytest.fixture
def env(tmp_path):
    store = Store(tmp_path / "test.db")
    bootstrap(store)
    gate = Gateway(store, demo_policy())
    return store, gate, gate.start_workflow("analyst")


def read(gate, workflow, resource="docs/finance-q4"):
    return gate.execute("analyst", workflow, {"operation": "read_document", "resource": resource})


def save(gate, workflow, resource="reports/test"):
    return gate.execute("analyst", workflow, {"operation": "save_report", "resource": resource, "content": "Derived summary"})


def deliver(gate, workflow, recipient="public-inbox", resource="reports/test"):
    return gate.execute("analyst", workflow, {"operation": "deliver", "resource": resource, "recipient": recipient})


def test_authorized_chain(env):
    store, gate, workflow = env
    assert read(gate, workflow).allowed
    result = save(gate, workflow)
    assert result.data["parents"] == ["docs/finance-q4"]
    assert result.effective_label == {"level": "CONFIDENTIAL", "compartments": ["FINANCE"]}
    assert deliver(gate, workflow, "finance-team").allowed
    assert len(store.inspect("inbox")) == 1
    assert len(store.inspect("executions")) == 3


def test_blocked_delivery_never_invokes_tool(env):
    store, gate, workflow = env
    read(gate, workflow)
    save(gate, workflow)
    with patch.object(gate, "_deliver", side_effect=AssertionError("must never be invoked")) as tool:
        result = deliver(gate, workflow)
    tool.assert_not_called()
    assert result.code == "RECIPIENT_CLEARANCE"
    assert not store.inspect("inbox")
    assert len(store.inspect("executions")) == 2
    assert store.events()[-1]["executed"] is False


@pytest.mark.parametrize("extra", [{"principal": "admin"}, {"label": "PUBLIC"}, {"policy": {"allow": True}}, {"skip_audit": True}, {"workflow": "clean"}])
def test_forged_authority_rejected(env, extra):
    store, gate, workflow = env
    result = gate.execute("analyst", workflow, {"operation": "read_document", "resource": "docs/hr-plan", **extra})
    assert result.code == "INVALID_ACTION"
    assert not store.inspect("executions")
    assert len(store.events()) == 1


@pytest.mark.parametrize("resource", ["../docs/hr-plan", "docs/../../secret", "docs\\hr-plan", "/etc/passwd", "docs/hr-plan/extra", "docs/%2e%2e", "docs/HR?x=1", "docs/hr-plan\n", "docs//hr-plan"])
def test_path_traversal_and_noncanonical_ids(env, resource):
    store, gate, workflow = env
    assert read(gate, workflow, resource).code == "INVALID_ACTION"
    assert not store.inspect("executions")


@pytest.mark.parametrize("proposal", [None, [], {}, {"operation": "shell", "resource": "docs/x"},
    {"operation": "deliver", "resource": "docs/public-brief", "recipient": "public-inbox", "content": "smuggled text"},
    {"operation": "read_document", "resource": "docs/public-brief", "content": "unexpected"},
    {"operation": "save_report", "resource": "reports/x", "content": "  "},
    {"operation": "save_report", "resource": "reports/x", "content": "x" * 50001}])
def test_invalid_schema_audited(env, proposal):
    store, gate, workflow = env
    result = gate.execute("analyst", workflow, proposal)
    assert result.code == "INVALID_ACTION"
    assert len(store.events()) == 1


def test_resume_preserves_workflow_and_artifact(env):
    store, gate, workflow = env
    read(gate, workflow, "docs/hr-plan")
    save(gate, workflow)
    restarted = Gateway(Store(store.path), demo_policy())
    assert deliver(restarted, workflow).code == "RECIPIENT_CLEARANCE"
    # Even a fresh context cannot launder the stored report's own label.
    fresh = restarted.start_workflow("analyst")
    assert deliver(restarted, fresh).code == "RECIPIENT_CLEARANCE"
    assert read(restarted, fresh, "reports/test").allowed
    assert save(restarted, fresh, "reports/second-generation").effective_label["level"] == "RESTRICTED"
    assert deliver(restarted, workflow, "hr-team").allowed


def test_combined_compartments(env):
    _, gate, workflow = env
    read(gate, workflow)
    read(gate, workflow, "docs/hr-plan")
    result = save(gate, workflow)
    assert result.effective_label == {"level": "RESTRICTED", "compartments": ["FINANCE", "HR"]}
    assert deliver(gate, workflow, "finance-team").code == "RECIPIENT_CLEARANCE"
    assert deliver(gate, workflow, "hr-team").code == "RECIPIENT_CLEARANCE"
    assert deliver(gate, workflow, "security-team").allowed


def test_workflow_highwater_cannot_be_reset_by_public_read(env):
    _, gate, workflow = env
    read(gate, workflow)
    read(gate, workflow, "docs/public-brief")
    assert save(gate, workflow).effective_label["level"] == "CONFIDENTIAL"
    assert deliver(gate, workflow, resource="docs/public-brief").code == "RECIPIENT_CLEARANCE"


def test_low_clearance_read_never_invokes_tool(env):
    store, gate, _ = env
    workflow = gate.start_workflow("viewer")
    with patch.object(gate, "_read_document") as tool:
        result = gate.execute("viewer", workflow, {"operation": "read_document", "resource": "docs/hr-plan"})
    tool.assert_not_called()
    assert result.code == "ACTOR_CLEARANCE"
    assert not store.inspect("executions")


def test_denied_save_never_invokes_tool(env):
    _, gate, workflow = env
    with patch.object(gate, "_save_report") as tool:
        result = save(gate, workflow, "docs/new")
    tool.assert_not_called()
    assert result.code == "WRITE_SCOPE"


def test_owner_and_unknown_identity(env):
    _, gate, workflow = env
    proposal = {"operation": "read_document", "resource": "docs/public-brief"}
    assert gate.execute("viewer", workflow, proposal).code == "WORKFLOW_OWNER"
    assert gate.execute("admin", workflow, proposal).code == "UNKNOWN_IDENTITY"
    assert read(gate, "nonexistent").code == "UNKNOWN_WORKFLOW"


def test_viewer_operation_denied(env):
    _, gate, _ = env
    workflow = gate.start_workflow("viewer")
    result = gate.execute("viewer", workflow, {"operation": "save_report", "resource": "reports/x", "content": "text"})
    assert result.code == "OPERATION_DENIED"


def test_unknown_and_scope(env):
    _, gate, workflow = env
    assert read(gate, workflow, "secrets/x").code == "READ_SCOPE"
    assert read(gate, workflow, "docs/missing").code == "NOT_FOUND"
    assert read(gate, workflow, "docs-evil/x").code == "READ_SCOPE"
    assert deliver(gate, workflow, "attacker", "docs/public-brief").code == "RECIPIENT_ALLOWLIST"


def test_immutable_reports(env):
    store, gate, workflow = env
    save(gate, workflow)
    before = store.inspect("artifacts")
    assert save(gate, workflow).code == "IMMUTABLE_ARTIFACT"
    assert store.inspect("artifacts") == before


def test_delivery_idempotency_under_concurrency(env):
    store, gate, workflow = env
    save(gate, workflow)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: deliver(gate, workflow), range(8)))
    assert sum(result.allowed for result in results) == 1
    assert len(store.inspect("inbox")) == 1
    assert sum(e["code"] == "DUPLICATE_DELIVERY" for e in store.events()) == 7
    assert store.verify_audit()


def test_audit_failure_rolls_back_tool(env):
    store, gate, workflow = env
    with patch.object(store, "audit", side_effect=RuntimeError("disk failure")):
        with pytest.raises(RuntimeError):
            save(gate, workflow)
    assert not any(a["kind"] == "report" for a in store.inspect("artifacts"))
    assert not store.inspect("executions")


def test_audit_redaction_and_tamper_detection(env):
    store, gate, workflow = env
    secret = "synthetic-secret-not-for-audit"
    gate.execute("analyst", workflow, {"operation": "save_report", "resource": "reports/x", "content": secret})
    assert secret not in json.dumps(store.events())
    assert store.verify_audit()
    with store.connection() as db:
        db.execute("UPDATE audit SET payload='{}' WHERE id=1")
    assert not store.verify_audit()


def test_content_tampering_blocks_read(env):
    store, gate, workflow = env
    with store.connection() as db:
        db.execute("UPDATE artifacts SET content='tampered' WHERE id='docs/finance-q4'")
    assert read(gate, workflow).code == "ARTIFACT_INTEGRITY"


@pytest.mark.parametrize("scenario,expected", [("authorized", [True, True, True]), ("injection", [True, False, True, False]),
    ("resume", [True, True, False, True]), ("compartments", [True, True, True, False, True])])
def test_live_scenario_contract(env, scenario, expected):
    store, _, _ = env
    result = run_scenario(store, scenario)
    assert [step["allowed"] for step in result["steps"]] == expected
    assert store.verify_audit()


@pytest.mark.parametrize("left", [Label(), Label(level="CONFIDENTIAL", compartments={"FINANCE"}), Label(level="RESTRICTED", compartments={"HR"})])
@pytest.mark.parametrize("right", [Label(), Label(level="INTERNAL"), Label(level="RESTRICTED", compartments={"HR"})])
def test_label_lattice_properties(left, right):
    joined = left.join(right)
    assert joined.dominates(left) and joined.dominates(right)
    assert joined == right.join(left)
    assert left.join(left) == left
