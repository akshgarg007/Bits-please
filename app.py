"""Trusted operator console. Run: streamlit run app.py"""
import json
import os
from pathlib import Path
import streamlit as st
from agentgate.demo import bootstrap, demo_policy, run_scenario
from agentgate.gateway import Gateway
from agentgate.store import Store

st.set_page_config(page_title="AGENTGATE · Trust at the boundary", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.block-container {padding-top:2rem; max-width:1440px}
h1 {letter-spacing:-.055em; font-weight:800!important}
h2,h3 {letter-spacing:-.025em}
[data-testid="stMetric"] {background:#111e30;border:1px solid #243449;border-radius:14px;padding:16px}
[data-testid="stSidebar"] {border-right:1px solid #243449}
.eyebrow {color:#58e8bb;letter-spacing:.16em;font-size:12px;font-weight:700}
.hero {padding:28px 32px;border:1px solid #2b4652;border-radius:18px;
background:linear-gradient(115deg,#122e31,#111e30 65%);margin-bottom:24px}
.hero h1 {font-size:48px;margin:8px 0}
.hero p {color:#acbed0;max-width:760px;font-size:17px}
.status {color:#58e8bb;font-size:12px;letter-spacing:.08em}
div.stButton>button {border-radius:9px}
</style>""", unsafe_allow_html=True)

db_path = Path(os.environ.get("AGENTGATE_DB", "data/agentgate.db"))
store = Store(db_path)
bootstrap(store)
policy = demo_policy()
gateway = Gateway(store, policy)

with st.sidebar:
    st.markdown("## ◈ AGENTGATE")
    st.caption("POLICY ENFORCEMENT LAB")
    st.divider()
    page = st.radio("Workspace", ["Overview", "Live scenarios", "Action playground", "Artifacts & inbox", "Audit explorer", "Policy & architecture"], label_visibility="collapsed")
    st.divider()
    st.markdown("**Local execution**")
    st.caption("SQLite persistence · deterministic policy\n\nNo API key or external delivery")
    st.success("Gateway online")
    st.caption("PS08 · Bits Please\n\nTrusted operator console. Identity switching is a demo control, not authentication. Synthetic records only.")

events = store.events()
allowed = sum(e["allowed"] for e in events)
blocked = len(events) - allowed


def metrics():
    cols = st.columns(4)
    for col, label, value in zip(cols, ["Decisions evaluated", "Authorized actions", "Blocked before execution", "Mock deliveries"],
                                 [len(events), allowed, blocked, len(store.inspect("inbox"))]):
        col.metric(label, value)


def show_decision(result):
    if result.allowed:
        st.success(f"ALLOW · {result.reason}")
    else:
        st.error(f"BLOCK · {result.code} · {result.reason}")
    st.caption(f"Audit event #{result.event_id} · Underlying tool {'executed' if result.allowed else 'not invoked'}")
    if result.effective_label:
        st.json(result.effective_label)
    if result.data:
        if "content" in result.data:
            st.code(result.data["content"], language=None)
        else:
            st.json(result.data)


if page == "Overview":
    st.markdown('''<div class="hero"><div class="eyebrow">TRUST AT THE EXECUTION BOUNDARY</div>
    <h1>Agents propose.<br>Policy decides.</h1>
    <p>A document can ask an agent to break the rules. It cannot grant permission.
    Inspect every decision, follow information across workflows, and see unsafe actions stop before execution.</p>
    <div class="status">● LIVE LOCAL PROTOTYPE &nbsp; / &nbsp; THREE PROTECTED TOOLS</div></div>''', unsafe_allow_html=True)
    metrics()
    st.write("")
    left, right = st.columns([1.6, 1])
    with left:
        st.subheader("The boundary that matters")
        st.graphviz_chart('''digraph G {rankdir=LR; bgcolor="transparent";
        node [shape=box style="rounded,filled" fillcolor="#111e30" color="#3a5269" fontcolor="#e5edf7" fontname="Arial"];
        edge [color="#58e8bb" fontcolor="#acbed0" fontname="Arial"];
        proposal [label="Untrusted\naction proposal"]; gate [label="AGENTGATE\nPolicy + information flow" color="#58e8bb"];
        tool [label="Protected tool\nRead · Save · Deliver"]; audit [label="Persistent audit\nAllow or deny"];
        proposal -> gate; gate -> tool [label="authorized"]; gate -> audit [label="every decision"];
        }''')
    with right:
        st.subheader("What to prove in 3 minutes")
        st.markdown("1. Deliver a finance report to an authorized team.\n2. Block a malicious memo's public-delivery instruction.\n3. Reopen the database and prove restrictions survive.\n4. Combine HR + finance and enforce both compartments.")
    st.divider()
    cols = st.columns(3)
    for col, title, body in zip(cols, ["01 / Permission before action", "02 / Labels travel with data", "03 / Evidence for every decision"],
                                ["Identity, operation, namespace and recipient are checked before the tool runs.",
                                 "Summaries inherit workflow sensitivity. Saving and reloading cannot downgrade it.",
                                 "Reason codes, policy fingerprints and execution status are recorded without document bodies."]):
        with col:
            st.markdown(f"**{title}**")
            st.caption(body)
    st.info("Open Live scenarios to execute the complete demonstration. All actions run against the real local gateway; there is no prerecorded replay or live LLM.")

elif page == "Live scenarios":
    st.title("Make the boundary visible.")
    st.caption("Deterministic proposals · live gateway execution · synthetic data")
    options = {"authorized": "01 · Authorized finance workflow", "injection": "02 · Prompt injection & forged classification",
               "resume": "03 · Restrictions after restart", "compartments": "04 · Mixed-source information flow"}
    scenario = st.selectbox("Scenario", list(options), format_func=options.get)
    descriptions = {
        "authorized": "Read confidential finance data, save a derived report, and deliver it to the finance team.",
        "injection": "An untrusted memo asks for PUBLIC reclassification and exfiltration. Both attempts must fail independently of the memo's wording.",
        "resume": "Create a restricted report, reconstruct the gateway with a new database connection, and attempt public then HR delivery.",
        "compartments": "Combine finance and HR data. A finance-only recipient must be rejected; the security team has both compartments.",
    }
    st.write(descriptions[scenario])
    if st.button("Run live scenario →", type="primary"):
        st.session_state["scenario_result"] = run_scenario(store, scenario)
    result = st.session_state.get("scenario_result")
    if result:
        st.subheader(options[result["scenario"]])
        st.caption(f"Workflow {result['workflow']} · new persistent records created on each run")
        for step in result["steps"]:
            with st.container(border=True):
                a, b = st.columns([3, 1])
                a.markdown(f"**{step['step']}**")
                (b.success if step["allowed"] else b.error)("ALLOW" if step["allowed"] else "BLOCK")
                st.write(step["reason"])
                label = step["effective_label"]
                st.caption(f"Event #{step['event_id']} · {step['code']}" + (f" · {label['level']} · {', '.join(label['compartments'])}" if label else ""))
        st.download_button("Download scenario evidence", json.dumps(result, indent=2), "scenario-evidence.json", "application/json")

elif page == "Action playground":
    st.title("Inspect an action. Challenge a policy.")
    st.caption("Trusted host controls appear on the left. The JSON proposal has no authority over identity, workflow or labels.")
    left, right = st.columns([1, 2])
    with left:
        principal = st.selectbox("Host-selected demo identity", list(policy.principals))
        workflows = [w for w in store.inspect("workflows") if w["principal"] == principal]
        if st.button("Create clean workflow"):
            workflow_id = gateway.start_workflow(principal)
            st.session_state["selected_workflow"] = workflow_id
            st.rerun()
        ids = [w["id"] for w in workflows]
        selected = st.session_state.get("selected_workflow")
        workflow = st.selectbox("Persistent workflow", ids, index=ids.index(selected) if selected in ids else 0) if ids else None
        if workflow:
            state = next(w for w in workflows if w["id"] == workflow)
            st.markdown("**Current information-flow label**")
            st.json(json.loads(state["label"]))
            st.caption("Read sources")
            st.write(json.loads(state["sources"]))
        else:
            st.info("Create a workflow to begin.")
        st.caption("A clean workflow requires a fresh agent context. Do not copy restricted context between workflows.")
    with right:
        presets = {
            "Read hostile memo": {"operation": "read_document", "resource": "docs/injected-memo"},
            "Save derived report": {"operation": "save_report", "resource": "reports/my-report", "content": "My derived report."},
            "Deliver to public": {"operation": "deliver", "resource": "reports/my-report", "recipient": "public-inbox"},
            "Deliver to finance": {"operation": "deliver", "resource": "reports/my-report", "recipient": "finance-team"},
            "Forge identity": {"operation": "read_document", "resource": "docs/hr-plan", "principal": "admin"},
            "Forge classification": {"operation": "save_report", "resource": "reports/forged", "content": "A summary", "label": "PUBLIC"},
        }
        preset = st.selectbox("Proposal starter", list(presets))
        proposal_text = st.text_area("Untrusted action JSON", json.dumps(presets[preset], indent=2), height=230, key="json-" + preset)
        if st.button("Evaluate & execute if authorized", type="primary", disabled=not workflow):
            try:
                proposal = json.loads(proposal_text)
            except json.JSONDecodeError:
                # Still route malformed input through schema validation + audit.
                proposal = None
            decision = gateway.execute(principal, workflow, proposal)
            st.session_state["playground_result"] = decision
            st.rerun()
        if "playground_result" in st.session_state:
            show_decision(st.session_state["playground_result"])

elif page == "Artifacts & inbox":
    st.title("Restrictions follow the artifact.")
    st.caption("Trusted operator view of synthetic records. This inspection console is not an agent tool or recipient-facing inbox.")
    artifacts = store.inspect("artifacts")
    st.dataframe([{"Resource": a["id"], "Kind": a["kind"], "Level": json.loads(a["label"])["level"],
                   "Compartments": ", ".join(json.loads(a["label"])["compartments"]), "Parents": ", ".join(json.loads(a["parents"]))}
                  for a in artifacts], width="stretch", hide_index=True)
    resource = st.selectbox("Inspect provenance", [a["id"] for a in artifacts])
    if resource:
        a = next(a for a in artifacts if a["id"] == resource)
        st.json({"resource": a["id"], "label": json.loads(a["label"]), "parents": json.loads(a["parents"]), "sha256": a["content_hash"]})
        with st.expander("Inspect synthetic content (trusted operator)"):
            st.code(a["content"], language=None)
    st.subheader("Mock inbox deliveries")
    inbox = store.inspect("inbox")
    if inbox:
        st.dataframe(inbox, width="stretch", hide_index=True)
    else:
        st.info("No deliveries yet. Authorized scenarios will populate this inbox.")

elif page == "Audit explorer":
    st.title("Every decision leaves evidence.")
    metrics()
    st.write("")
    if store.verify_audit():
        st.success("Stored audit hash chain is internally consistent.")
    else:
        st.error("Audit integrity check failed. Investigate modified records.")
    st.caption("Hash chaining detects accidental edits; it does not resist a database administrator who rewrites the chain. Document bodies are excluded.")
    decision_filter = st.selectbox("Decision filter", ["All", "Blocked", "Allowed"])
    rows = [e for e in events if decision_filter == "All" or e["allowed"] == (decision_filter == "Allowed")]
    if rows:
        st.dataframe([{k: e[k] for k in ["event_id", "timestamp", "principal", "operation", "resource", "recipient", "code", "executed"]} for e in reversed(rows)], width="stretch", hide_index=True)
        event_id = st.selectbox("Inspect full decision", [e["event_id"] for e in reversed(rows)])
        st.json(next(e for e in rows if e["event_id"] == event_id))
    else:
        st.info("No matching decisions. Run a scenario to generate live evidence.")
    st.download_button("Export complete audit JSON", json.dumps(events, indent=2), "agentgate-audit.json", "application/json")

elif page == "Policy & architecture":
    st.title("Policy is trusted. Proposals are not.")
    st.markdown("**PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED**")
    st.write("A recipient must dominate the sensitivity level and possess every required compartment. Combining sources takes the maximum level and the union of compartments.")
    st.code("report.label = join(all documents read in this workflow)\ndelivery.label = join(workflow.label, artifact.label)\nallow_delivery = permissions_pass AND recipient.clearance.dominates(delivery.label)", language="python")
    st.subheader("Trusted policy snapshot")
    st.json(policy.model_dump(mode="json"))
    st.caption("Policy fingerprint: " + gateway.policy_hash)
    st.subheader("Scope & honest limitations")
    st.markdown("- Local single-operator prototype, with synthetic data and a mock inbox.\n- No live LLM is required. Scenarios generate deterministic adversarial proposals.\n- The host, policy, database and process are trusted. Arbitrary code execution in the host is out of scope.\n- No declassification tool is exposed: report classifications cannot be lowered.\n- A resumed workflow keeps its context label; a new workflow must use a clean planner context.\n- UI inspection and downloadable audit records are privileged operator capabilities.\n- SQLite transactions cover local tools; a real email adapter would require an outbox and idempotency design.")
