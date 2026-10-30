"""Exercise the Streamlit application as a user, including live interactions."""
from pathlib import Path
from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "app.py"


def test_dashboard_navigation_and_scenario(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_DB", str(tmp_path / "ui.db"))
    app = AppTest.from_file(str(APP)).run(timeout=30)
    assert not app.exception
    for page in ["Live scenarios", "Action playground", "Artifacts & inbox", "Audit explorer", "Policy & architecture", "Overview"]:
        app.sidebar.radio[0].set_value(page).run()
        assert not app.exception, page
    app.sidebar.radio[0].set_value("Live scenarios").run()
    app.selectbox[0].set_value("injection").run()
    app.button[0].click().run()
    assert not app.exception
    assert len(app.error) == 2
    assert sum(message.value == "ALLOW" for message in app.success) == 2


def test_playground_live_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_DB", str(tmp_path / "ui.db"))
    app = AppTest.from_file(str(APP)).run(timeout=30)
    app.sidebar.radio[0].set_value("Action playground").run()
    app.button[0].click().run()
    assert not app.exception
    app.button[1].click().run()
    assert not app.exception
    assert any("ALLOW" in message.value for message in app.success)
