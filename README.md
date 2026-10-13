# AI SOC Analyst

An explainable, classical-AI cybersecurity decision-support lab. It runs six deterministic sample incidents through alert prioritization, graph investigation, evidence scoring, Minimax response planning, and a human approval step. All response effects are confined to an in-memory simulated environment; the application does not connect to real security tools or networks.

## Run the lab

Requirements: Python 3.10 or newer.

From the `backend` directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn main:app --reload
```

Open <http://127.0.0.1:8000>. FastAPI serves the separate `frontend/` files and exposes the backend under `/api`. Use the theme control to switch between light and dark; the choice is remembered in the browser. Seeded alerts are inserted only when their IDs are absent, so analyst status is retained in `backend/ai_soc_analyst.db` across restarts. **Reset run** restores seed alert statuses and simulated environment state, and archives generated alerts while preserving history.

## Operating the simulated alert stream

Use the **Incoming alert stream** controls on the dashboard to start, pause, or resume scenario-generated alerts. Choose an arrival interval and a random seed; **Reset run** clears active generated alerts, restores seeded alert statuses and the simulated environment, and applies the selected seed so the sequence can be repeated. The dashboard receives resumable updates over a server-sent event stream. Active generated alert retention is capped at 100; older records remain in SQLite history.

The activity panel replays Hill Climbing candidate swaps, BFS graph visits, threat scoring, and Minimax attacker-response comparisons as each alert is processed. The alert detail shows BFS shortest paths and its explored search tree. A confirmed finding receives a response plan that requires a human decision. All input data and response effects are simulated; no real network telemetry or controls are used. See [DEMO_AND_TEAM_GUIDE.md](DEMO_AND_TEAM_GUIDE.md) for a prepared walkthrough, likely viva questions, and a teammate briefing.

Run the backend checks from the `backend` directory:

```powershell
python -m unittest discover -s tests -v
```

## Workflow

1. **Prioritize:** Hill Climbing searches for a higher-scoring alert order. The objective weights high-priority alerts earlier in the queue.
2. **Investigate:** Breadth-First Search (BFS) traverses the alert graph and returns a shortest path to each configured observation. The dashboard shows the explored nodes and tree branches.
3. **Assess:** The threat score sums the points for the scenario's simulated observations, capped at 100. Scores of 60 or more are `CONFIRMED`, 30–59 are `SUSPICIOUS`, and lower scores are `BENIGN`.
4. **Recommend:** Minimax compares fixed, illustrative attacker-response outcomes for four defensive actions and chooses the smallest worst-case damage score.
5. **Approve:** The analyst approves or rejects the recommendation. Approval changes only the simulated environment view.

## Scope and limitations

- Scenario observations are deterministic and keyed by alert type. They are teaching data, not live evidence or threat intelligence.
- Minimax uses a small hand-authored damage matrix. It is an algorithm demonstration, not an operational risk model.
- Alert records, evidence, workflow, response decisions, and history persist in SQLite. At startup, the environment replays persisted approved containment actions so the dashboard agrees with responded alerts. Pending recommendations are recomputed from the saved alert data.
- There is no user authentication. Keep the development server bound to localhost; do not expose it to an untrusted network.
- This prototype is not a SIEM, EDR, production SOC service, or autonomous response agent.

## Project layout

- `backend/main.py` — FastAPI routes and frontend hosting
- `backend/algorithms/` — Hill Climbing, BFS, and Minimax
- `backend/data/` — sample scenarios and investigation graphs
- `backend/engines/` — workflow orchestration and scoring
- `backend/models/` — alerts and simulated environment
- `frontend/` — standalone SOC dashboard (HTML, CSS, and JavaScript)
- `backend/tests/` — repeatable workflow checks
