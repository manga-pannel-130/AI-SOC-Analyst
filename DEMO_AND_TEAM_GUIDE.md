# Professor walkthrough and teammate briefing

This guide describes what the current code actually does. The system is a local, explainable AI SOC decision-support prototype using generated scenario data. It does not ingest real network traffic or contain production response integrations.

## 5-minute professor walkthrough

### Before the meeting

1. Start the backend from `backend` with the README commands and open `http://127.0.0.1:8000`.
2. Keep the demo on localhost. The API has no authentication and is not safe to expose to a public or untrusted network.
3. Use the light/dark control if useful, then set the seed to `2026` and the arrival interval to `5` seconds.
4. Start with the stream paused so you can explain the seeded queue first. The generated stream is deterministic for a chosen seed, but generated alert IDs include a run identifier.

### Suggested narration and clicks

**0:00 — State the problem and boundary.** “A SOC analyst receives more alerts than can be reviewed in arrival order. This system demonstrates a transparent triage and response workflow. Its inputs are generated lab scenarios; it is not connected to a real network.” Point out the source label and human-approval requirement.

**0:30 — Explain prioritization.** Point to one alert’s factor breakdown: severity, frequency, asset criticality, business impact, confidence, and evidence score. Explain that Hill Climbing searches pairwise swaps to improve a weighted queue objective. The objective is the sum of each alert’s priority score multiplied by its queue-position weight, so higher-scoring alerts should move earlier. Open the live trace and show candidate swaps, accepted moves, evaluations, and the stopping reason. Be clear that this is a simple local-search heuristic, not a globally optimal scheduler.

**1:20 — Show incoming telemetry and the end-to-end workflow.** Start the stream. An alert arrives from the scenario generator, is persisted to SQLite, then the event stream updates the console. The processing workflow performs BFS investigation, evidence scoring, response planning, and queue reprioritization. Let the live activity panel show actual BFS node visits, the classification score, and Minimax outcomes. Select the arriving alert to show its graph, evidence paths, and priority factors.

**2:20 — Explain investigation and classification.** Expand an investigation tree. BFS starts at `Alert`, visits nodes breadth-first, and finds a shortest path to each observed evidence node. The evidence is generated from a hand-authored profile for the scenario type and signal strength; it is simulated evidence, not threat-intelligence lookup. The scoring table assigns positive points to suspicious observations and negative points to benign observations, clamps the total to 0–100, then classifies ≥60 as confirmed, 30–59 suspicious, and below 30 benign.

**3:10 — Explain Minimax and analyst control.** For a confirmed alert, show the response plan. Each available defensive action is evaluated against modeled attacker replies. The planner takes each action’s worst modeled damage, then selects the action with the lowest worst case. Emphasize that the outcome values and attacker reactions are authored assumptions, not learned or calibrated production estimates. Approve or reject only if you are comfortable applying a change in this local simulation. Show that approval changes the simulated environment view and persists the alert decision; no real endpoint, account, or IP is changed.

**4:10 — Show persistence, reset, and limitations.** Point to recent processed history, pause/resume, interval control, and repeatable seed. Explain that workflow records are stored in SQLite, simulated environment state is reconstructed from persisted approved actions after restart, and reset restores the seed alerts/environment while archiving generated alerts. End by naming the next production steps: real telemetry adapters, identity and access controls, a calibrated evidence model, audit/retention policy, integration tests, and carefully permissioned response connectors.

### A compact finish

“My contribution is an end-to-end explainable workflow: rank alerts, investigate a graph, score evidence, compare response options adversarially, and leave the final action to an analyst. The current build is a local simulation that validates the workflow and its explanations. It is a foundation for later integration work, not a production SOC product yet.”

## Likely professor questions and defensible answers

### Problem and scope

- **What problem are you solving?** Helping analysts triage a queue and see why an alert is ranked, how evidence was found, and how a response recommendation was compared.
- **Is this connected to a real network or SIEM?** No. Alerts and evidence are generated from local scenario data. The environment is an in-memory model. The app currently has no SIEM/EDR connector.
- **Why call it an AI SOC Analyst if it uses classic algorithms?** “AI” here describes explicit search and decision methods. BFS, Hill Climbing, and Minimax are classical AI techniques. There is no machine-learning model or LLM.
- **What is the project’s limitation?** The conclusions depend on authored scenarios, evidence scores, priority weights, and attacker-response assumptions. They demonstrate explainable mechanics, not real-world detection accuracy.
- **Can this become production grade?** The architecture can be extended, but the current code is not production-ready. Productionization needs secure ingestion, authentication/authorization, validated data, calibrated models, durable audit trails, robust operations, and integrations with safeguards.

### Algorithms

- **Why Hill Climbing?** It makes queue-order changes explainable as swaps and is easy to inspect. It can stop at a local optimum and does not prove the best possible ordering. The implementation bounds candidate evaluations to protect runtime.
- **What is the objective function?** For queue position `i`, it adds `priority_score(alert) × (queue_size - i)`. Higher scores gain more when they appear earlier.
- **Why use BFS?** Each investigation graph is unweighted; BFS returns a shortest path in edge count and naturally yields an explainable visit order/tree. DFS-based search was removed so the interface focuses on the selected graph-search method.
- **What does BFS prove?** It proves the shortest path in this configured graph to an observed node. It does not prove the observation is true or malicious.
- **How is threat score computed?** The threat engine adds the configured evidence points, including negative points for benign indicators, clamps the total to 0–100, then applies fixed thresholds.
- **How does Minimax work here?** It evaluates available defensive actions against a small list of modeled attacker reactions, takes the maximum damage for each action, and chooses the action with the minimum maximum.
- **Is Minimax modeling a fully rational attacker?** Only in a small, hand-authored outcome table. It is a teaching approximation, and its assumptions must not be presented as empirical.

### Backend, storage, and security

- **What does FastAPI do?** Serves the dashboard and exposes JSON API routes for alerts, investigation, prioritization, response decisions, environment state, history, and simulation controls.
- **Why SQLite?** It is a simple local persistence layer for alert data, workflow results, response decisions, and history. It avoids an external database dependency for the lab.
- **What is persisted and what is simulated in memory?** Alert/workflow/decision records are stored in SQLite. The environment is in memory and is reconstructed from approved persisted response actions on startup.
- **How does the live UI update?** A server-sent event stream sends sequenced events; the browser resumes using the last event ID and requests a state resync if its cursor falls outside retained history.
- **What happens when a response is approved?** The backend checks the alert is confirmed and its plan is eligible, then applies the selected action to the simulated environment and persists the decision.
- **Is the app secure for deployment?** No. It has no authentication and is intended to run locally. It must not be exposed to an untrusted network.
- **How do you limit simulator growth?** Active generated alerts are capped and older ones are archived; the event replay window and candidate-evaluation work are also bounded.

### Testing and evaluation

- **How would you evaluate detection quality?** The current scenarios are authored, so they cannot establish real detection performance. A later evaluation needs labeled, representative datasets, train/test separation where applicable, false-positive/negative analysis, and analyst review.
- **What tests should be added next?** API lifecycle and status-transition tests, persistence/restart tests, simulation concurrency and SSE replay tests, malformed input tests, and browser workflow/accessibility checks. Existing backend unit tests exercise representative algorithm and workflow behavior but do not replace integration or security testing.
- **How would you validate the score thresholds?** Compare against labeled incidents and analyst decisions, measure false positives/negatives by scenario and asset type, and tune thresholds with documented risk trade-offs.
- **How would you avoid unsafe automated response?** Require role-based authorization, approval policy, change audit, idempotency, rollback paths, dry-run mode, connector-specific safeguards, and a tested containment plan. Current build only simulates actions.

## Teammate briefing (share this)

“AI SOC Analyst is a local cybersecurity decision-support project. It turns generated security-alert scenarios into a complete, explainable workflow. FastAPI is the backend; the separate HTML/CSS/JavaScript dashboard is the frontend; SQLite stores alerts, analysis, decisions, and history.

The workflow has four main algorithmic parts. Hill Climbing orders the alert queue using severity, frequency, asset importance, business impact, confidence, and threat evidence. BFS explores a scenario investigation graph and shows the shortest route to each observed signal. A rule-based scorer adds or subtracts points for suspicious or benign evidence, then labels the result benign, suspicious, or confirmed. Minimax compares available defensive actions against modeled attacker reactions and recommends the action with the smallest worst-case damage. A human must approve or reject the recommendation; approval only changes the simulated environment.

The simulator can stream repeatable alerts, and the dashboard shows the live algorithm trace, alert detail, environment, and saved history. It is intentionally honest about its current scope: it has no live telemetry, learned detection model, SIEM/EDR connector, authentication, or production response action. The project demonstrates a classical-AI workflow and gives us a base to extend toward real integrations with proper security and validation.”

## One-minute project explanation

“AI SOC Analyst is an explainable alert-triage prototype. It ranks incoming alerts with Hill Climbing, investigates each scenario graph with BFS, scores the resulting simulated evidence, and uses Minimax to compare possible responses against modeled attacker behavior. Analysts see the reasoning and must approve any simulated action. FastAPI, SQLite, and a separate web dashboard make up the application. Today it runs on generated lab data only; it is a foundation for integrating real telemetry and carefully controlled response systems later, not a production SOC service.”
