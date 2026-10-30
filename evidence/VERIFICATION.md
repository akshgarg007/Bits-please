# Local verification — 30 October 2026

Environment: Windows, Python 3.12.14. Exact installed packages are recorded in `environment.txt`.

## Automated tests

Command: `python -m pytest -q`

```text
52 passed in 13.06s
```

Coverage includes the three protected tool boundaries, malformed and forged actions, clearance and compartments, workflow ownership, namespace escapes, restart persistence, immutable artifacts, concurrent duplicate delivery, audit rollback, content fingerprints, audit edits and Streamlit navigation/interaction.

An initial UI assertion incorrectly counted the sidebar status as a scenario ALLOW. It was corrected to count explicit ALLOW results; the complete suite was rerun successfully.

## Labeled synthetic evaluation

Command: `python -m agentgate.evaluate --output evidence/evaluation.json`

- 16 / 16 expected authorization decisions and reason codes matched.
- 12 expected denials; zero protected tool executions for those cases.
- 16 / 16 evaluated actions added exactly one audit event.
- Median decision latency: 16.960 ms; maximum: 24.511 ms on this local run.
- Every case reconstructed the gateway and database handle before its final evaluated action.

This small synthetic evaluation is regression evidence, not an independent security assessment. Latency includes local transaction/audit work and varies by machine.

## Demonstration

Command: `python -m agentgate --db data/verification.db --scenario all`

Output saved in `scenarios.json`. Four live scenarios completed, with a valid audit chain and four authorized mock deliveries. No external message was sent.

## UI verification

Streamlit AppTest exercised all six views and the injection scenario/playground. A localhost browser preview confirmed the overview rendered with the hero, metrics, architecture diagram and navigation. No claim of cross-browser or mobile-device certification is made.

GitHub Actions is configured for Python 3.11 and 3.12 on Ubuntu; local results do not imply those remote jobs have run.
