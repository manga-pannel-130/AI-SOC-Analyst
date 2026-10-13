const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? "—").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const state = { alerts: [], visibleAlerts: [], selected: null, investigation: null, recommendation: null, environment: null, priority: null, simulation: null, refreshing: false, refreshQueued: false, algorithmPlayback: false, pendingPriority: null, workflowQueue: [], history: [] };
let eventSource;

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
  return payload;
}
function wait(milliseconds) { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }
function toast(message, error = false) {
  const el = document.createElement("div"); el.className = `toast ${error ? "error" : "success"}`; el.textContent = message;
  $("#toast-region").append(el); setTimeout(() => el.remove(), 3500);
}
function riskClass(score) { return score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : "low"; }
function statusClass(status) { return `status-${String(status || "NEW").toLowerCase().replaceAll("_", "-")}`; }

function updateSimulationUI(simulation) {
  state.simulation = simulation;
  if (simulation.type === "reset") $("#simulation-seed").value = simulation.seed;
  const intervalSelect = $("#simulation-interval");
  if (intervalSelect && simulation.interval) intervalSelect.value = String(simulation.interval);
  const status = simulation.running ? (simulation.paused ? "PAUSED" : "RUNNING") : "IDLE";
  const badge = $("#simulation-status");
  badge.textContent = status;
  badge.className = `simulation-status ${status.toLowerCase()}`;
  const sidebarBadge = document.querySelector(".lab-badge");
  sidebarBadge.classList.toggle("inactive", !simulation.running || simulation.paused);
  $("#sidebar-simulation-state").textContent = `SIMULATION ${status}`;
  $("#simulation-toggle").innerHTML = simulation.running && !simulation.paused ? "Pause stream <span>Ⅱ</span>" : simulation.running ? "Resume stream <span>▶</span>" : "Start stream <span>▶</span>";
  $("#simulation-count").textContent = simulation.generated_count;
  $("#simulation-seed-label").textContent = simulation.seed;
  $("#simulation-rate").textContent = simulation.running
    ? `New alert every ${simulation.interval} sec`
    : `One alert every ${simulation.interval || 20} sec · waiting to start`;
  if (!$("#simulation-seed").value) $("#simulation-seed").value = simulation.seed;
}
function renderEmptyDetail() {
  $("#detail").innerHTML = '<div class="empty"><div class="empty-orbit"><span>◎</span></div><h2>Choose an alert to begin</h2><p>Review its signals, walk the investigation paths, then decide whether to approve a simulated response.</p></div>';
}
function setAlgorithmState(heading, caption, status = "RUNNING") {
  $("#algorithm-heading").textContent = heading;
  $("#algorithm-caption").textContent = caption;
  $("#algorithm-state").textContent = status;
}
function addAlgorithmStep(title, detail, result = "", kind = "") {
  const list = $("#algorithm-steps");
  list.querySelector(".activity-empty")?.remove();
  const item = document.createElement("div");
  item.className = `activity-step ${kind}`;
  const number = String(list.children.length + 1).padStart(2, "0");
  item.innerHTML = `<span class="step-number">${number}</span><span><b>${esc(title)}</b><small>${esc(detail)}</small></span><span class="step-result">${esc(result)}</span>`;
  list.append(item);
  while (list.children.length > 14) list.firstElementChild.remove();
  list.scrollTop = list.scrollHeight;
}
function addLiveEvent(alert, generatedCount) {
  const list = $("#live-events");
  list.querySelector(".activity-empty")?.remove();
  const item = document.createElement("div");
  const score = Number(alert.priority_score || 0);
  item.className = `event-entry ${score >= 80 ? "critical-event" : ""}`;
  item.innerHTML = `<span class="event-time">${new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"})}</span><span><b>${esc(alert.alert_type.replaceAll("_", " "))} · ${esc(alert.id)}</b><small>${esc(alert.asset_id || "Unassigned asset")} · score ${score.toFixed(0)} · event ${generatedCount}</small></span>`;
  list.prepend(item);
  while (list.children.length > 12) list.lastElementChild.remove();
}
function renderHistory(alerts) {
  state.history = alerts;
  $("#history-count").textContent = `${alerts.length} SAVED`;
  $("#history-list").innerHTML = alerts.length ? alerts.map((alert) => `<button class="history-item" data-id="${esc(alert.id)}" type="button"><span><b>${esc(alert.alert_type.replaceAll("_", " "))}</b><small>${esc(alert.id)} · ${esc(alert.created_at || "saved")}</small></span><span class="status-pill ${statusClass(alert.status)}">${esc(alert.status.replaceAll("_", " "))}</span></button>`).join("") : '<div class="activity-empty">No processed alerts have been saved yet.</div>';
  document.querySelectorAll(".history-item").forEach((row) => row.addEventListener("click", () => selectAlert(row.dataset.id)));
}
async function playLiveWorkflow(event, dequeued = false) {
  if (!dequeued) {
    if (state.workflowQueue.length >= 8) state.workflowQueue.shift();
    state.workflowQueue.push(event);
  }
  if (state.algorithmPlayback) return;
  const next = state.workflowQueue.shift();
  const eventEpoch = next.alert?.run_id || state.simulation?.run_id;
  state.algorithmPlayback = true;
  $("#algorithm-steps").innerHTML = "";
  const paths = next.investigation?.evidence_paths || [];
  setAlgorithmState("BFS · live investigation", `${paths.length} evidence path(s) · actual graph visit order.`, "SEARCHING");
  try {
    for (const item of paths) {
      const result = item.bfs;
      addAlgorithmStep(`Search for ${item.node}`, `BFS starts at Alert · shortest path depth ${result.depth}`, "TARGET");
      for (const [index, node] of (result.visit_order || result.explored_nodes || []).entries()) {
        if (eventEpoch && eventEpoch !== state.simulation?.run_id) return;
        addAlgorithmStep(`Visit ${node}`, `Evidence target: ${item.node} · breadth-first visit ${index + 1}`, node === item.node ? "FOUND" : `DEPTH ${result.depth}`);
        await wait(90);
      }
      addAlgorithmStep(`Evidence collected: ${item.node}`, `Path: ${(result.path || []).join(" → ")}`, `+${next.assessment?.evidence?.find((entry) => entry.node === item.node)?.points || 0} PTS`, "improved");
    }
    const assessment = next.assessment || {};
    addAlgorithmStep(`Classify ${assessment.classification || "unknown"}`, `Evidence score ${assessment.score ?? "—"}/100 · confirmed ≥60, suspicious ≥30`, "ASSESSMENT");
    const plan = next.response_plan;
    if (plan?.trace?.length) {
      setAlgorithmState("Minimax · response planning", "Each defensive action is tested against modeled attacker replies.", "EVALUATING");
      for (const action of plan.trace) {
        const replies = action.responses || action.attacker_responses || [];
        addAlgorithmStep(`Defend with ${action.action.replaceAll("_", " ")}`, `${replies.length} modeled attacker response(s)`, `WORST ${action.worst_case_damage}`);
        for (const reply of replies) {
          addAlgorithmStep(`Attacker: ${reply.response.replaceAll("_", " ")}`, `Outcome if ${action.action.replaceAll("_", " ")} is used`, `${reply.damage}/100`);
          await wait(100);
        }
      }
      addAlgorithmStep(`Recommend ${plan.recommended_action.replaceAll("_", " ")}`, "Lowest worst-case damage · analyst approval required.", `WORST ${plan.worst_case_damage}`, "improved");
    }
    setAlgorithmState("Workflow complete", `${next.message || "Evidence, classification and response planning complete."} Review the alert and make the human decision.`, "COMPLETE");
  } finally {
    state.algorithmPlayback = false;
    await playPendingPriority();
    if (state.workflowQueue.length) playLiveWorkflow(state.workflowQueue.shift(), true);
  }
}
function handleSimulationEvent(event) {
  if (event.type === "state" || event.type === "reset") updateSimulationUI(event);
  if (event.type === "alert") {
    if (state.simulation && event.epoch !== state.simulation.epoch) return;
    addLiveEvent(event.alert, event.generated_count);
    $("#simulation-count").textContent = event.generated_count;
    refresh();
  }
  if (event.type === "workflow_complete") {
    if (event.alert && !state.selected) {
      state.selected = event.alert;
      state.investigation = { alert: event.alert, investigation: event.investigation, threat_assessment: event.assessment };
      state.recommendation = event.response_plan;
      renderDetail();
    }
    refresh();
    playLiveWorkflow(event);
  }
  if (event.type === "pipeline_error") {
    addAlgorithmStep("Workflow error", `${event.stage || "processing"}: ${event.message || "The alert could not be processed."}`, "REVIEW", "rejected");
    toast(`Alert processing failed: ${event.message || event.stage}`, true);
    refresh();
  }
  if (event.type === "resync_required") {
    if (event.state) updateSimulationUI(event.state);
    refresh();
  }
  if (event.type === "reset") {
    state.alerts = [];
    state.selected = null;
    state.investigation = null;
    state.recommendation = null;
    state.pendingPriority = null;
    state.workflowQueue = [];
    renderEmptyDetail();
    $("#live-events").innerHTML = '<div class="activity-empty">Waiting for the first simulated alert.</div>';
    $("#algorithm-steps").innerHTML = '<div class="activity-empty">Algorithm steps will appear here as the simulation runs.</div>';
    setAlgorithmState("Algorithm activity", "Start the simulation or investigate an alert to watch the algorithms work.", "READY");
    refresh();
  }
}
function seededShuffle(items, seed) {
  const result = [...items];
  let value = Number(seed) >>> 0;
  for (let index = result.length - 1; index > 0; index--) {
    value = (Math.imul(value, 1664525) + 1013904223) >>> 0;
    const swap = value % (index + 1);
    [result[index], result[swap]] = [result[swap], result[index]];
  }
  return result;
}
async function animatePriority(ranked, byId) {
  const trace = ranked.trace || [];
  const evaluations = Number(ranked.candidate_evaluations ?? trace.filter((item) => item.type === "candidate").length);
  const captured = trace.filter((item) => item.type === "candidate").length;
  const finalAlerts = ranked.alerts.map((item) => ({ ...byId.get(item.id), ...item })).filter((alert) => alert.id);
  if (state.algorithmPlayback) {
    state.alerts = finalAlerts;
    state.priority = ranked;
    state.pendingPriority = { ranked, byId };
    applyFilters();
    return;
  }
  const alertMap = new Map(finalAlerts.map((alert) => [alert.id, alert]));
  setAlgorithmState("Hill Climbing · priority queue", "Evaluating swaps to move higher-scoring alerts toward the front.", "OPTIMIZING");
  $("#algorithm-steps").innerHTML = "";
  const delay = Math.min(55, Math.max(12, 700 / Math.max(1, trace.length)));
  for (const step of trace) {
    if (step.type === "start") {
      addAlgorithmStep("Random starting queue", `${step.order.length} alerts · objective ${Number(step.score).toLocaleString()}`, `${step.order.length} alerts`);
    } else if (step.type === "candidate") {
      const positions = (step.swap || []).map((index) => `#${index + 1}`).join(" ↔ ");
      addAlgorithmStep(`Evaluate swap ${positions}`, `Candidate objective ${Number(step.score).toLocaleString()}`, step.improves ? "IMPROVES" : "REJECT", step.improves ? "improved" : "rejected");
    } else if (step.type === "move") {
      state.alerts = step.order.map((id) => alertMap.get(id)).filter(Boolean);
      state.priority = ranked;
      applyFilters();
      addAlgorithmStep("Accept best neighbor", `Queue rearranged · objective ${Number(step.score).toLocaleString()}`, "MOVED", "improved");
    } else if (step.type === "complete") {
      addAlgorithmStep(step.stop_reason === "evaluation_limit" ? "Search evaluation limit reached" : "Local optimum reached", `${step.iterations} pass(es) · ${evaluations} neighbor evaluations`, `SCORE ${Number(step.score).toLocaleString()}`);
    }
    await wait(delay);
  }
  state.alerts = finalAlerts;
  state.priority = ranked;
  applyFilters();
  const traceNote = `${ranked.trace_truncated ? ` Showing ${captured} trace steps of ${evaluations} evaluations.` : ""}${ranked.stop_reason === "evaluation_limit" ? " Search stopped at the configured evaluation limit." : ""}`;
  setAlgorithmState("Hill Climbing · priority queue", `${evaluations} candidate swaps evaluated; higher-scoring alerts are placed earlier.${traceNote}`, "COMPLETE");
}
async function playPendingPriority() {
  if (!state.pendingPriority) return;
  const pending = state.pendingPriority;
  state.pendingPriority = null;
  await animatePriority(pending.ranked, pending.byId);
}

async function refresh() {
  if (state.refreshing) {
    state.refreshQueued = true;
    return;
  }
  state.refreshing = true;
  try {
    const [summary, all, environment, simulation, history] = await Promise.all([
      api("/api/dashboard"),
      api("/api/alerts"),
      api("/api/environment"),
      api("/api/simulation"),
      api("/api/history?limit=20")
    ]);
    renderHistory(history.alerts || []);
    const byId = new Map(all.alerts.map((alert) => [alert.id, alert]));
    updateSimulationUI(simulation);
    const available = all.alerts;
    let initialOrder;
    if (!state.alerts.length) {
      initialOrder = seededShuffle(available, simulation.seed).map((alert) => alert.id);
    } else {
      initialOrder = state.alerts.map((alert) => alert.id).filter((id) => byId.has(id));
      const known = new Set(initialOrder);
      initialOrder.push(...available.filter((alert) => !known.has(alert.id)).map((alert) => alert.id));
    }
    state.alerts = initialOrder.map((id) => byId.get(id)).filter(Boolean);
    state.environment = environment;
    state.priority = null;
    renderSummary(summary); applyFilters(); renderEnvironment();
    const ranked = await api("/api/prioritize", {
      method: "POST",
      body: JSON.stringify({ initial_order: initialOrder })
    });
    await animatePriority(ranked, byId);
    if (state.selected) {
      const fresh = byId.get(state.selected.id);
      if (fresh) { state.selected = { ...fresh, ...ranked.alerts.find((item) => item.id === fresh.id) }; renderDetail(); }
    }
  } catch (error) { toast(error.message, true); }
  finally {
    state.refreshing = false;
    if (state.refreshQueued) {
      state.refreshQueued = false;
      setTimeout(refresh, 0);
    }
  }
}

function renderSummary(data) {
  const open = state.alerts.filter((alert) => !["RESPONDED", "RESPONSE_REJECTED", "BENIGN"].includes(alert.status)).length;
  const online = data.environment.assets.filter((asset) => asset.status === "ONLINE").length;
  const cards = [
    ["Total alerts", data.total_alerts, "Scenario signals loaded", "aqua", "◉"],
    ["Critical priority", data.critical, "Score 80 and above", "rose", "↗"],
    ["Awaiting review", open, "Human decision pending", "gold", "◷"],
    ["Assets online", `${online}/${data.environment.assets.length}`, "Simulated endpoints", "blue", "▦"],
  ];
  $("#summary").innerHTML = cards.map(([label,value,note,tone,icon]) => `<article class="metric-card ${tone}"><div class="metric-top"><span>${esc(label)}</span><span class="metric-icon">${icon}</span></div><div class="metric-value">${esc(value)}</div><div class="metric-note">${esc(note)}</div><div class="metric-spark"></div></article>`).join("");
  $("#nav-count").textContent = data.total_alerts;
}
function applyFilters() {
  const query = $("#search").value.trim().toLowerCase(); const status = $("#status-filter").value;
  state.visibleAlerts = state.alerts.filter((alert) => {
    const matchesQuery = !query || [alert.id, alert.alert_type, alert.description, alert.asset_id, alert.username].some((value) => String(value || "").toLowerCase().includes(query));
    return matchesQuery && (status === "ALL" || alert.status === status);
  });
  renderAlerts();
}
function renderAlerts() {
  $("#queue-count").textContent = `${state.visibleAlerts.length} / ${state.alerts.length}`;
  const ranked = state.priority || {};
  $("#sort-score").textContent = `Queue objective ${Number(ranked.state_score || 0).toLocaleString()}  ·  ${ranked.iterations || 0} search passes`;
  if (!state.visibleAlerts.length) { $("#alerts").innerHTML = `<div class="no-results">No alerts match this view.</div>`; return; }
  $("#alerts").innerHTML = state.visibleAlerts.map((alert, index) => `<button class="alert-row ${state.selected?.id === alert.id ? "active" : ""}" data-id="${esc(alert.id)}" type="button">
    <span class="rank">${String(index + 1).padStart(2,"0")}</span><span class="alert-copy"><span class="alert-name">${esc(alert.alert_type.replaceAll("_"," "))}</span><span class="alert-sub">${esc(alert.id)} <i>·</i> ${esc(alert.asset_id || "No asset")}</span></span>
    <span class="alert-score"><b>${Number(alert.priority_score).toFixed(0)}</b><small>PRIORITY</small></span><span class="status-pill ${statusClass(alert.status)}">${esc(alert.status.replaceAll("_"," "))}</span><span class="chevron">›</span>
  </button>`).join("");
  document.querySelectorAll(".alert-row").forEach((row) => row.addEventListener("click", () => selectAlert(row.dataset.id)));
}
function selectAlert(id) {
  state.selected = state.alerts.find((alert) => alert.id === id) || state.history.find((alert) => alert.id === id);
  state.investigation = state.selected?.investigation ? { alert: state.selected, investigation: state.selected.investigation, threat_assessment: { score: state.selected.threat_score, classification: state.selected.threat_classification, evidence: state.selected.evidence || [] } } : null;
  state.recommendation = state.selected?.response_plan || null;
  document.querySelectorAll(".alert-row").forEach((row) => row.classList.toggle("active", row.dataset.id === id));
  renderDetail();
}
function fact(label, value, hint = "") { return `<div class="fact"><span>${esc(label)}</span><b>${esc(value)}</b>${hint ? `<small>${esc(hint)}</small>` : ""}</div>`; }
function renderPriority(a) {
  const breakdown = a.factor_breakdown || {};
  const parts = Object.entries(breakdown).map(([key, factor]) => {
    const value = Number(factor.value || 0); const weight = Number(factor.weight || 0); const points = Number(factor.points || 0);
    return `<div class="factor-row"><div class="factor-title"><span>${esc(key.replaceAll("_"," "))}</span><b>${value}/10 <i>→</i> ${points.toFixed(1)} pts</b></div><div class="factor-track"><span style="width:${Math.min(100,value*10)}%"></span></div><small>Weight ${(weight*100).toFixed(0)}% · contributes ${points.toFixed(1)} to the score</small></div>`;
  }).join("");
  return `<section class="content-section" id="priority"><div class="section-heading"><div><span class="eyebrow">01 · ATTENTION ORDER</span><h3>Hill Climbing priority</h3></div><span class="method-pill">LOCAL SEARCH</span></div><div class="priority-layout"><div class="score-orb ${riskClass(a.priority_score)}"><strong>${Number(a.priority_score).toFixed(0)}</strong><span> / 100</span><small>PRIORITY SCORE</small></div><div class="factor-list">${parts}</div></div><div class="algorithm-footnote"><b>Queue objective</b> ${Number(state.priority?.state_score || 0).toLocaleString()} <span>·</span> <b>Iterations</b> ${esc(state.priority?.iterations || 0)} <span>·</span> alerts ranked by score-weighted position</div></section>`;
}
function searchTrace(name, result) {
  const tree = (result.tree_edges || []).map((edge) => `<span class="tree-edge">${esc(edge.parent)} <i>→</i> ${esc(edge.child)}</span>`).join("");
  return `<div class="trace-block"><div class="trace-top"><b>${name}</b><span>${result.found ? "PATH FOUND" : "NO PATH"}</span></div><div class="trace-meta"><span>Depth ${esc(result.depth)}</span><span>${result.explored_nodes.length} explored</span></div><div class="path-flow">${result.path.length ? result.path.map((node,i)=>`${i ? '<span class="flow-arrow">→</span>' : ""}<span class="flow-node">${esc(node)}</span>`).join("") : '<span class="muted">No path found</span>'}</div><details class="explored"><summary>Investigation tree (${(result.tree_edges || []).length} branches)</summary><div class="tree-edges">${tree || '<span class="muted">No reachable branches</span>'}</div><div class="node-list">${result.explored_nodes.map((node,i)=>`<span>${String(i+1).padStart(2,"0")} ${esc(node)}</span>`).join("")}</div></details></div>`;
}
function renderInvestigation() {
  const result = state.investigation?.investigation; const assessment = state.investigation?.threat_assessment;
  if (!result || !assessment) return `<div class="placeholder"><span>⌘</span><div><b>Investigation not run</b><small>BFS traverses the scenario graph and finds the shortest path to each observed signal.</small></div></div>`;
  const evidence = result.evidence_paths.map((item) => `<article class="evidence-path"><div class="evidence-path-head"><span class="evidence-dot"></span><b>${esc(item.node)}</b><span class="evidence-points">+${assessment.evidence.find((e)=>e.node===item.node)?.points || 0} pts</span></div><div class="trace-grid">${searchTrace("BFS",item.bfs)}</div></article>`).join("");
  return `<div class="assessment-banner ${riskClass(assessment.score)}"><div class="assessment-score"><b>${assessment.score}</b><small>/ 100</small></div><div><span class="eyebrow">THREAT CLASSIFICATION</span><strong>${esc(assessment.classification)}</strong><p>Score threshold: confirmed ≥ 60 · suspicious ≥ 30 · benign &lt; 30</p></div><span class="assessment-check">${assessment.classification === "CONFIRMED" ? "✓" : "◌"}</span></div><div class="evidence-total"><span>Evidence points collected</span><b>${assessment.evidence.reduce((n,e)=>n+e.points,0)} pts <i>·</i> capped at 100</b></div><div class="evidence-paths">${evidence}</div>`;
}
function renderMinimax() {
  const rec = state.recommendation;
  if (!rec) return `<div class="placeholder"><span>⤴</span><div><b>No response plan yet</b><small>Minimax compares defensive actions against modeled attacker reactions.</small></div></div>`;
  const alternatives = rec.alternatives.map((item) => `<article class="action-card ${item.action === rec.recommended_action ? "recommended" : ""}"><div class="action-card-head"><b>${esc(item.action.replaceAll("_"," "))}</b>${item.action === rec.recommended_action ? '<span class="recommended-tag">SELECTED</span>' : ""}<strong>${esc(item.worst_case_damage)}<small> WORST CASE</small></strong></div><div class="attacker-replies">${item.attacker_responses.map((reply)=>`<div><span>↳ ${esc(reply.response.replaceAll("_"," "))}</span><b>${esc(reply.damage)}</b></div>`).join("")}</div><div class="damage-track"><span style="width:${item.worst_case_damage}%"></span></div></article>`).join("");
  const decisionControls = state.selected?.archived ? '<div class="approval-box"><div><b>Archived run</b><small>This historical alert is read-only.</small></div></div>' : `<div class="approval-box"><div><b>Analyst decision</b><small>Approval applies this action only to the simulated environment.</small></div><div class="actions"><button class="button approve" id="approve">Approve response <span>→</span></button><button class="button reject" id="reject">Reject</button></div></div>`;
  return `<div class="recommendation-banner"><span class="rec-icon">✦</span><div><small>MINIMAX RECOMMENDS</small><b>${esc(rec.recommended_action.replaceAll("_"," "))}</b></div><span class="damage-score">${esc(rec.worst_case_damage)}<small> WORST CASE</small></span></div><p class="reasoning">${esc(rec.reasoning)}</p><div class="action-comparison">${alternatives}</div>${decisionControls}`;
}
function renderDetail() {
  const a = state.selected; if (!a) return;
  const confirmed = a.status === "CONFIRMED" && !a.archived;
  const investigation = state.investigation;
  $("#detail").innerHTML = `<div class="incident-head"><div class="incident-title"><div class="eyebrow">INCIDENT FILE <span> / </span>${esc(a.id)}</div><h2>${esc(a.alert_type.replaceAll("_"," "))}</h2><p>${esc(a.description)}</p></div><span class="status-pill large ${statusClass(a.status)}">${esc(a.status.replaceAll("_"," "))}</span></div>
    <div class="incident-facts">${fact("Asset",a.asset_id)}${fact("Account",a.username)}${fact("Source address",a.source_ip)}${fact("Destination",a.destination_ip)}${fact("Business impact",`${a.business_impact}/10`)}${fact("Confidence",`${a.confidence}/10`)}</div>
    <div class="detail-actions"><button class="button primary" id="investigate" ${a.archived ? "disabled title=\"Archived alerts are read-only\"" : ""}>${investigation ? "↻ Re-run investigation" : "Run investigation"}<span>⌘</span></button><span class="step-hint">${a.archived ? "Archived record · read only" : "1. Assess evidence&nbsp;&nbsp; 2. Review response&nbsp;&nbsp; 3. Approve or reject"}</span></div>
    ${renderPriority(a)}
    <section class="content-section" id="investigation"><div class="section-heading"><div><span class="eyebrow">02 · GRAPH SEARCH</span><h3>Investigation & evidence</h3></div><span class="method-pair">BREADTH-FIRST SEARCH</span></div>${renderInvestigation()}</section>
    <section class="content-section" id="response"><div class="section-heading"><div><span class="eyebrow">03 · ADVERSARIAL PLANNING</span><h3>Minimax response plan</h3></div><button class="button outline" id="recommend" ${confirmed ? "" : "disabled title=\"Confirm the threat before requesting a response plan\""}>${state.recommendation ? "↻ Recalculate" : "Generate plan"}<span>✦</span></button></div>${!confirmed ? '<div class="locked-note"><span>⌑</span> Confirmed threat assessment is required before generating a response plan.</div>' : renderMinimax()}</section>
    <div class="incident-disclaimer"><span>ⓘ</span> Lab simulation only. No real IPs, accounts, endpoints, or network controls are changed.</div>`;
  if (!a.archived) $("#investigate").addEventListener("click", runInvestigation);
  $("#recommend").addEventListener("click", recommend);
  $("#approve")?.addEventListener("click", () => applyDecision("approve"));
  $("#reject")?.addEventListener("click", () => applyDecision("reject"));
}
function renderEnvironment() {
  if (!state.environment) return;
  const env = state.environment;
  const assets = env.assets.map((asset)=>`<article class="asset-card ${asset.status === "ISOLATED" ? "isolated" : ""}"><div class="asset-glyph">${asset.asset_type.toLowerCase().includes("server") ? "▤" : "▣"}</div><div class="asset-copy"><b>${esc(asset.asset_id)}</b><small>${esc(asset.hostname)} · ${esc(asset.asset_type)}</small></div><span class="asset-state ${asset.status === "ONLINE" ? "online" : "isolated-state"}"><i></i>${esc(asset.status)}</span><span class="criticality">${esc(asset.criticality)}<small>/10</small></span></article>`).join("");
  const blocks = env.blocked_ips.length ? env.blocked_ips.map((ip)=>`<span class="env-tag blocked">IP BLOCKED · ${esc(ip)}</span>`).join("") : '<span class="empty-state">No blocked IP addresses</span>';
  const users = env.disabled_users.length ? env.disabled_users.map((name)=>`<span class="env-tag disabled">USER DISABLED · ${esc(name)}</span>`).join("") : '<span class="empty-state">No disabled accounts</span>';
  $("#environment-content").innerHTML = `<div class="asset-list">${assets}</div><div class="env-actions-state"><div><span class="eyebrow">NETWORK CONTAINMENT</span><div class="env-tags">${blocks}</div></div><div><span class="eyebrow">IDENTITY CONTROLS</span><div class="env-tags">${users}</div></div></div>`;
}
async function playInvestigationTrace() {
  const paths = state.investigation?.investigation?.evidence_paths || [];
  const playbackEpoch = state.simulation?.epoch;
  state.algorithmPlayback = true;
  $("#algorithm-steps").innerHTML = "";
  setAlgorithmState("BFS · graph investigation", `${paths.length} simulated evidence target(s) · replaying explored-node order.`, "SEARCHING");
  try {
    for (const item of paths) {
      for (const algorithm of ["BFS"]) {
        if (playbackEpoch !== state.simulation?.epoch) break;
        const result = item[algorithm.toLowerCase()];
        const nodes = result.explored_nodes || [];
        addAlgorithmStep(`${algorithm} → ${item.node}`, `Starting graph traversal · depth ${result.depth}`, `${nodes.length} nodes`);
        const delay = Math.min(60, Math.max(18, 360 / Math.max(1, nodes.length)));
        for (let index = 0; index < nodes.length; index++) {
          if (playbackEpoch !== state.simulation?.epoch) break;
          addAlgorithmStep(`${algorithm} visits ${nodes[index]}`, `Evidence target: ${item.node} · explored ${index + 1}/${nodes.length}`, result.found && nodes[index] === item.node ? "FOUND" : `DEPTH ${result.depth}`);
          await wait(delay);
        }
        addAlgorithmStep(`${algorithm} complete`, result.found ? `Path found at depth ${result.depth}` : "No path found", result.found ? "PATH FOUND" : "NO PATH", result.found ? "improved" : "rejected");
      }
    }
    if (playbackEpoch === state.simulation?.epoch) {
      setAlgorithmState("BFS · graph investigation", "Traversal order and shortest evidence paths are shown in the selected alert's investigation panel.", "COMPLETE");
    }
  } finally {
    state.algorithmPlayback = false;
    await playPendingPriority();
  }
}
async function playMinimaxTrace() {
  const alternatives = state.recommendation?.trace || [];
  const playbackEpoch = state.simulation?.epoch;
  state.algorithmPlayback = true;
  $("#algorithm-steps").innerHTML = "";
  setAlgorithmState("Minimax · response planning", "Evaluating each defensive action against its modeled attacker replies.", "EVALUATING");
  try {
    for (const action of alternatives) {
      if (playbackEpoch !== state.simulation?.epoch) break;
      const replies = action.responses || action.attacker_responses || [];
      addAlgorithmStep(`Evaluate ${action.action.replaceAll("_", " ")}`, `${replies.length} modeled attacker response(s)`, `WORST ${action.worst_case_damage}`);
      for (const reply of replies) {
        if (playbackEpoch !== state.simulation?.epoch) break;
        addAlgorithmStep(`Attacker: ${reply.response.replaceAll("_", " ")}`, `Damage if ${action.action.replaceAll("_", " ")} is chosen`, `${reply.damage}/100`);
        await wait(160);
      }
    }
    if (playbackEpoch === state.simulation?.epoch) {
      addAlgorithmStep(`Select ${state.recommendation.recommended_action.replaceAll("_", " ")}`, "Minimax chooses the action with the lowest worst-case damage.", `WORST ${state.recommendation.worst_case_damage}`, "improved");
      setAlgorithmState("Minimax · response planning", "Review the modeled outcomes, then approve or reject the simulated response.", "COMPLETE");
    }
  } finally {
    state.algorithmPlayback = false;
    await playPendingPriority();
  }
}
async function runInvestigation() {
  const button = $("#investigate"); button.disabled = true; button.classList.add("loading");
  try {
    state.investigation = await api(`/api/investigate/${encodeURIComponent(state.selected.id)}`, { method:"POST" });
    state.selected = { ...state.selected, ...state.investigation.alert }; state.recommendation = null;
    await refresh(); await playInvestigationTrace();
    toast(`Assessment complete · ${state.investigation.threat_assessment.classification}`);
  } catch (error) { toast(error.message, true); }
  finally { if (button.isConnected) { button.disabled = false; button.classList.remove("loading"); } }
}
async function recommend() {
  const button = $("#recommend"); button.disabled = true;
  try {
    state.recommendation = await api(`/api/recommend-response/${encodeURIComponent(state.selected.id)}`, { method:"POST" });
    renderDetail();
    await playMinimaxTrace();
  }
  catch (error) { toast(error.message, true); if (button.isConnected) button.disabled = false; }
}
async function applyDecision(kind) {
  const buttons = document.querySelectorAll("#approve, #reject"); buttons.forEach((button)=>button.disabled=true);
  try {
    const result = await api(`/api/${kind}-response/${encodeURIComponent(state.selected.id)}`, { method:"POST" });
    if (!result.success) throw new Error(result.message);
    state.recommendation = null; toast(kind === "approve" ? "Approved · simulated action applied" : "Recommendation rejected");
    await refresh();
  } catch (error) { toast(error.message, true); buttons.forEach((button)=>{if(button.isConnected)button.disabled=false;}); }
}
function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("soc-theme", theme);
  const light = theme === "light";
  $("#theme-icon").textContent = light ? "◐" : "☼";
  $("#theme-label").textContent = light ? "Dark mode" : "Light mode";
  document.querySelector('meta[name="theme-color"]').content = light ? "#f5f7fb" : "#0b1220";
}
async function toggleSimulation() {
  const simulation = state.simulation || {};
  const path = simulation.running
    ? simulation.paused ? "/api/simulation/resume" : "/api/simulation/pause"
    : "/api/simulation/start";
  const button = $("#simulation-toggle");
  button.disabled = true;
  try { updateSimulationUI(await api(path, { method: "POST" })); }
  catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}
async function configureSimulation() {
  const intervalSelect = $("#simulation-interval");
  if (!intervalSelect) {
    toast("Alert interval control is missing. Reload the dashboard.", true);
    return;
  }
  try {
    updateSimulationUI(await api("/api/simulation/configure", {
      method: "POST",
      body: JSON.stringify({ interval: Number(intervalSelect.value) })
    }));
    toast("Alert arrival interval updated");
  } catch (error) { toast(error.message, true); }
}
async function resetSimulation() {
  const seed = Number($("#simulation-seed").value);
  if (!Number.isInteger(seed) || seed < 0) {
    toast("Enter a non-negative whole-number seed.", true);
    return;
  }
  const button = $("#simulation-reset");
  button.disabled = true;
  try {
    const simulation = await api("/api/simulation/reset", {
      method: "POST",
      body: JSON.stringify({ seed })
    });
    handleSimulationEvent(simulation);
    toast(`Run reset · seed ${seed}`);
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}
function connectEventStream() {
  eventSource = new EventSource("/api/events");
  eventSource.onmessage = (message) => {
    try { handleSimulationEvent(JSON.parse(message.data)); }
    catch (error) { toast(`Could not read a simulation event: ${error.message}`, true); }
  };
  eventSource.onerror = () => {
    $("#simulation-rate").textContent = "Reconnecting to event stream…";
  };
}
$("#refresh").addEventListener("click", refresh);
$("#search").addEventListener("input", applyFilters);
$("#status-filter").addEventListener("change", applyFilters);
$("#theme-toggle").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
$("#simulation-toggle").addEventListener("click", toggleSimulation);
$("#simulation-reset").addEventListener("click", resetSimulation);
$("#simulation-interval").addEventListener("change", configureSimulation);
document.querySelectorAll(".nav-link").forEach((link)=>link.addEventListener("click",()=>{document.querySelectorAll(".nav-link").forEach((item)=>item.classList.remove("selected"));link.classList.add("selected");}));
setTheme(localStorage.getItem("soc-theme") || "dark");
setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}); }, 1000);
connectEventStream();
refresh();
