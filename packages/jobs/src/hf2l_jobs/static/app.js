/* HF²L dashboard: same-origin session cookies, no browser token persistence. */
"use strict";
(() => {
  const BASE = "/api/jobs/v1";
  const $ = (id) => document.getElementById(id);
  const STATES = ["QUEUED", "PROVISIONING", "STARTING", "RUNNING", "RECONCILING", "NEEDS_ATTENTION", "CANCELLING", "SUCCEEDED", "FAILED", "CANCELLED"];
  const state = {session: null, catalog: null, view: "current", job: null, tab: "overview",
    cursor: null, next: null, previous: [], page: 1, search: "", filter: "",
    stream: null, streamLive: false, reconnect: null, reconnectDelay: 3000,
    refreshTimer: null, refreshing: false, refreshAgain: false, authenticated: false,
    action: null, createRequest: null, supplemental: {}, enrollments: {}, logCursor: null, logs: [], logNext: null};
  const node = (tag, cls, text) => {
    const item = document.createElement(tag);
    if (cls) item.className = cls;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  };
  const append = (parent, ...children) => {children.flat(Infinity).filter(Boolean).forEach((child) => parent.append(child)); return parent;};
  const human = (value) => String(value || "Unknown").toLowerCase().replaceAll("_", " ").replaceAll(".", " ").replace(/^./, (c) => c.toUpperCase());
  const list = (value) => Array.isArray(value) ? value : (value && (value.items || value.results)) || [];
  const identity = (job) => job.id || job.job_id;
  const name = (job) => job.name || job.display_name || job.spec?.name || identity(job);
  const spec = (job) => job.spec || job.specification || {};
  const when = (value, detailed = false) => {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) return "—";
    return date.toLocaleString(undefined, detailed ? {dateStyle: "medium", timeStyle: "short"} : {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"});
  };
  const elapsed = (value) => {
    if (!value) return "—";
    const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).valueOf()) / 1000));
    if (!Number.isFinite(seconds)) return "—";
    if (seconds < 60) return "Less than a minute";
    if (seconds < 3600) return Math.floor(seconds / 60) + " min";
    if (seconds < 86400) return Math.floor(seconds / 3600) + " hr " + Math.floor(seconds % 3600 / 60) + " min";
    return Math.floor(seconds / 86400) + " days " + Math.floor(seconds % 86400 / 3600) + " hr";
  };
  const bytes = (value) => {
    const n = Number(value);
    if (!Number.isFinite(n)) return "—";
    if (n >= 1073741824) return (n / 1073741824).toFixed(1).replace(/\.0$/, "") + " GiB";
    if (n >= 1048576) return (n / 1048576).toFixed(0) + " MiB";
    return n + " bytes";
  };
  const badge = (value) => node("span", "badge " + String(value || "unknown").toLowerCase().replace(/[^a-z0-9_]/g, ""), human(value));
  const empty = (title, description) => append(node("div", "empty-state"), node("h2", "", title), node("p", "", description));
  const button = (text, fn, cls = "") => {const el = node("button", "button " + cls, text); el.type = "button"; el.addEventListener("click", fn); return el;};
  const actions = (job) => Array.isArray(job.allowed_actions) ? job.allowed_actions : Object.keys(job.allowed_actions || {}).filter((key) => job.allowed_actions[key]);
  const version = (job) => '"' + String(job.version) + '"';
  const uuid = () => crypto.randomUUID ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(16))).map((n) => n.toString(16).padStart(2, "0")).join("");
  const notice = (id, text) => {$(id).textContent = text || ""; $(id).hidden = !text;};
  const toast = (message) => {const el = node("div", "toast", message); $("toast-region").append(el); setTimeout(() => el.remove(), 6500);};
  const operator = () => (state.session?.permissions || []).includes("platform_operator");
  const query = (values) => {const q = new URLSearchParams(); for (const [key, value] of Object.entries(values)) if (value !== null && value !== undefined && value !== "") q.set(key, value); return q.toString();};
  function errorMessage(error) {
    const code = error.code || "";
    const help = {
      job_version_conflict: "This job changed. Refresh it before trying again.",
      stale_job_version: "This job changed. Refresh it before trying again.",
      version_conflict: "This job changed. Refresh it before trying again.",
      job_deadline_expired: "This job's original deadline has expired. Create a new job for a new duration budget.",
      final_admin_required: "Keep at least one job administrator.",
      last_admin_required: "Keep at least one job administrator.",
      last_job_admin_required: "Keep at least one job administrator.",
      runtime_active: "The runtime must be confirmed stopped before this action.",
      idempotency_conflict: "This request key was already used with different inputs. Reopen the form and try again.",
      invalid_reconciliation_evidence: "Provide verified publication or nonpublication evidence.",
      job_not_found: "This job is unavailable or your access has been removed."
    };
    const detail = typeof error.detail === "string" ? error.detail : "";
    return help[code] || detail || (code ? human(code) : error.message || "The request failed. Try again.");
  }
  async function api(path, options = {}) {
    const target = path.startsWith("/auth/") || path.startsWith(BASE + "/") ? path : BASE + path;
    const settings = {method: options.method || "GET", credentials: "same-origin", cache: "no-store", headers: {"Accept": "application/json"}};
    if (settings.method !== "GET") {
      settings.headers["X-CSRF-Token"] = state.session?.csrf_token || "";
      settings.headers["Idempotency-Key"] = options.key || uuid();
      if (options.job) settings.headers["If-Match"] = version(options.job);
      if (options.body !== undefined) {settings.headers["Content-Type"] = "application/json"; settings.body = JSON.stringify(options.body);}
    }
    let response;
    try {response = await fetch(target, settings);} catch (_) {const err = new Error("The job manager could not be reached. Your input is preserved; check the connection and retry."); err.code = "network_error"; throw err;}
    let result = {};
    try {result = await response.json();} catch (_) {if (response.ok && response.status !== 204) throw new Error("The job manager returned an unreadable response.");}
    if (!response.ok) {
      if (response.status === 401) expireSession();
      const info = result.error || result;
      const err = new Error(typeof info.detail === "string" ? info.detail : response.statusText);
      err.code = info.code || (response.status === 409 ? "version_conflict" : "request_failed");
      err.detail = info.detail;
      err.status = response.status;
      throw err;
    }
    return result;
  }
  function expireSession() {
    state.authenticated = false;
    if (state.stream) state.stream.close();
    clearTimeout(state.reconnect);
    state.streamLive = false;
    $("application").hidden = true; $("login-panel").hidden = false;
    $("identity").textContent = ""; $("logout-button").hidden = true;
    $("jobs-content").replaceChildren(); $("detail-panel").replaceChildren(); $("operations-panel").replaceChildren(); $("summary").replaceChildren();
    state.job = null; state.supplemental = {}; state.logs = [];
    document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
    connection("Session expired", false);
    notice("session-notice", "");
    $("login-panel").querySelector("p").textContent = "Your session expired or access was revoked. Sign in again to retrieve current authorization.";
  }
  function connection(label, live) {
    $("connection-label").textContent = label;
    $("connection-dot").className = "connection-dot " + (live ? "live" : label.startsWith("Polling") ? "" : "offline");
  }
  function connectEvents() {
    if (!state.authenticated || state.stream) return;
    const stream = new EventSource(BASE + "/events/stream", {withCredentials: true});
    state.stream = stream;
    stream.onopen = () => {state.streamLive = true; state.reconnectDelay = 3000; connection("Live updates", true);};
    const invalidate = () => {scheduleRefresh();};
    stream.addEventListener("invalidated", invalidate);
    stream.addEventListener("reset", () => {resetPagination(); scheduleRefresh();});
    stream.addEventListener("session_expired", expireSession);
    stream.onerror = () => {
      state.streamLive = false;
      connection("Polling every 10 seconds", false);
      // Native EventSource preserves its opaque Last-Event-ID when reconnecting.
      // Leave it open so the browser, rather than JavaScript, owns reconnection.
      if (!state.authenticated) {stream.close(); state.stream = null;}
    };
  }
  function scheduleRefresh() {
    clearTimeout(state.refreshTimer);
    state.refreshTimer = setTimeout(refresh, 250);
  }
  function resetPagination() {state.cursor = null; state.next = null; state.previous = []; state.page = 1;}
  function route() {
    const raw = location.hash.slice(1) || "current";
    const [path, params] = raw.split("?");
    const segments = path.split("/");
    document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
    const nextView = segments[0] === "job" ? "job" : (["current", "queued", "history", "operations"].includes(segments[0]) ? segments[0] : "current");
    if (nextView !== state.view) {resetPagination(); state.search = ""; state.filter = ""; $("job-search").value = ""; $("state-filter").value = "";}
    state.view = nextView;
    state.tab = new URLSearchParams(params || "").get("tab") || "overview";
    if (!["overview", "logs", "artifacts", "access"].includes(state.tab)) state.tab = "overview";
    try {state.jobId = nextView === "job" ? decodeURIComponent(segments[1] || "") : null;} catch (_) {state.jobId = ""; }
    state.logCursor = null; state.logs = []; state.logNext = null;
    document.querySelectorAll(".nav-link").forEach((link) => {const selected = link.dataset.view === state.view; link.classList.toggle("active", selected); if (selected) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");});
    $("list-panel").hidden = ["job", "operations"].includes(state.view);
    $("summary").hidden = ["job", "operations"].includes(state.view);
    $("detail-panel").hidden = state.view !== "job";
    $("operations-panel").hidden = state.view !== "operations";
    const titles = {current: ["Current jobs", "Follow active training and resource provisioning."], queued: ["Job queue", "Resource requests waiting for admission. Queue reasons are current; no estimated start time is implied."], history: ["Job history", "Completed, cancelled, and failed jobs you are authorized to access."], job: ["Job detail", "Private job progress, execution history, and retained results."], operations: ["Resource health", "Capacity, sandbox qualification, quarantine, and cleanup for platform operators."]};
    $("page-title").textContent = titles[state.view][0]; $("page-description").textContent = titles[state.view][1]; $("breadcrumb-title").textContent = titles[state.view][0];
    $("page-eyebrow").textContent = state.view === "operations" ? "Platform operations" : "Federated learning";
    updateStateOptions();
    refresh();
  }
  function updateStateOptions() {
    const possible = state.view === "queued" ? ["QUEUED"] : state.view === "history" ? ["SUCCEEDED", "FAILED", "CANCELLED"] : STATES.filter((value) => !["QUEUED", "SUCCEEDED", "FAILED", "CANCELLED"].includes(value));
    const select = $("state-filter"); select.replaceChildren(node("option", "", "All states")); select.firstElementChild.value = "";
    possible.forEach((value) => {const o = node("option", "", human(value)); o.value = value; select.append(o);});
    select.value = state.filter;
  }
  async function refresh() {
    if (!state.authenticated) return;
    if (state.refreshing) {state.refreshAgain = true; return;}
    state.refreshing = true; $("refresh-button").disabled = true;
    notice("page-error", "");
    const routeKey = location.hash;
    try {
      if (state.view === "job") await loadJob(routeKey);
      else if (state.view === "operations") await loadOperations();
      else await loadList(routeKey);
      $("updated-label").textContent = "Updated " + new Date().toLocaleTimeString(undefined, {hour: "2-digit", minute: "2-digit", second: "2-digit"});
    } catch (error) {
      if (state.authenticated) {
        notice("page-error", errorMessage(error));
        if (state.cursor && ["invalid_cursor", "cursor_expired"].includes(error.code)) {resetPagination(); state.refreshAgain = true;}
        if (state.view === "job" && [403, 404].includes(error.status)) {state.job = null; $("detail-panel").replaceChildren(empty("Job unavailable", "Your current authorization does not permit access to this job."));}
      }
    } finally {
      state.refreshing = false; $("refresh-button").disabled = false;
      if (state.refreshAgain) {state.refreshAgain = false; scheduleRefresh();}
    }
  }
  function renderSummary(counts) {
    const fields = [
      ["Running", counts?.running ?? counts?.RUNNING, "Admitted training jobs", "green"],
      ["Queued", counts?.queued ?? counts?.QUEUED, "Waiting for resources", "amber"],
      ["Preparing", counts?.preparing ?? ((counts?.PROVISIONING !== undefined && counts?.STARTING !== undefined) ? counts.PROVISIONING + counts.STARTING : undefined), "Provisioning or starting", "blue"],
      ["Historical", counts?.history ?? counts?.historical, "Retained job outcomes", ""]
    ];
    $("summary").replaceChildren(...fields.map(([label, value, caption, color]) => append(node("div", "summary-card"), append(node("div", "summary-top"), node("span", "", label), node("span", "summary-indicator " + color)), node("strong", "summary-value", value ?? "—"), node("span", "summary-caption", caption))));
    $("queue-nav-count").textContent = counts?.queued ?? counts?.QUEUED ?? "";
  }
  function roundValues(job) {return [Number(job.current_round ?? job.rounds?.current ?? 0), Number(job.target_round ?? job.rounds?.target ?? spec(job).target_round ?? 0)];}
  function progress(job) {
    const [current, target] = roundValues(job);
    const element = node("progress"); element.max = Math.max(1, target); element.value = Math.min(current, element.max); element.setAttribute("aria-label", "Global round progress");
    return append(node("div", "progress-line"), append(node("div", "progress-track"), element), node("span", "mono", target ? current + " / " + target : String(current)));
  }
  function resourceSummary(job) {
    if (job.resource_summary) return (Number(job.resource_summary.cpu_millicores || 0) / 1000).toLocaleString() + " CPU · " + bytes(job.resource_summary.memory_bytes);
    const components = spec(job).components || job.components || [];
    const cpu = components.reduce((sum, c) => sum + Number(c.resources?.cpu_millicores || 0), 0);
    const mem = components.reduce((sum, c) => sum + Number(c.resources?.memory_bytes || 0), 0);
    return cpu ? (cpu / 1000).toLocaleString() + " CPU · " + bytes(mem) : "Not yet reported";
  }
  function queueReason(job) {
    const reason = job.queue_reason;
    if (!reason) return job.phase ? human(job.phase) : "Waiting for capacity";
    if (typeof reason === "string") return human(reason);
    return reason.message || reason.detail || human(reason.code || reason.reason);
  }
  async function loadList(routeKey) {
    const params = query({view: state.view, search: state.search, state: state.filter, limit: 25, cursor: state.cursor});
    const result = await api("/jobs?" + params);
    if (location.hash !== routeKey) return;
    const jobs = list(result);
    const counts = {...result.counts, ...result.summary};
    if (result.counts_by_state) STATES.forEach((value) => {counts[value] = Number(result.counts_by_state[value] || 0);});
    renderSummary(counts);
    state.next = result.next_cursor || null;
    $("next-page").disabled = !state.next; $("previous-page").disabled = state.previous.length === 0;
    $("page-number").textContent = "Page " + state.page;
    $("list-count").textContent = jobs.length + (jobs.length === 1 ? " job on this page" : " jobs on this page");
    if (!jobs.length) {
      const labels = {current: ["No current jobs", "Create a job to start training, or view queued work and retained outcomes."], queued: ["The queue is clear", "No accessible jobs are waiting for resources."], history: ["No historical jobs", "Finished jobs will remain here with their history and retention status."]};
      $("jobs-content").replaceChildren(empty(state.search || state.filter ? "No matching jobs" : labels[state.view][0], state.search || state.filter ? "Change the search or state filter to find accessible jobs." : labels[state.view][1]));
      return;
    }
    const table = node("table"); const head = node("thead"); const header = node("tr");
    ["Job", "State & phase", state.view === "queued" ? "Resource wait" : "Global rounds", "Resources", "Created"].forEach((label) => header.append(node("th", "", label)));
    head.append(header); table.append(head); const body = node("tbody");
    jobs.forEach((job) => {
      const row = node("tr"); const title = node("a", "job-name", name(job)); title.href = "#job/" + encodeURIComponent(identity(job));
      const titleCell = append(node("td"), title, node("span", "secondary mono", identity(job)));
      const phase = String(job.state).toUpperCase() === "QUEUED" ? queueReason(job) : human(job.phase || "");
      const stateCell = append(node("td"), badge(job.state), job.phase || job.queue_reason ? node("span", "secondary", phase) : null);
      const progressCell = state.view === "queued" ? append(node("td"), node("span", "", elapsed(job.queued_at || job.created_at)), node("span", "secondary", queueReason(job))) : append(node("td"), progress(job));
      const resourceCell = append(node("td"), node("span", "", resourceSummary(job)), node("span", "secondary", (spec(job).components || []).map((c) => c.resources?.pool_id).filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(", ")));
      append(row, titleCell, stateCell, progressCell, resourceCell, node("td", "", when(job.created_at)));
      body.append(row);
    });
    table.append(body); $("jobs-content").replaceChildren(append(node("div", "table-scroll"), table));
  }
  function keyValues(values) {
    const dl = node("dl", "key-values");
    values.forEach(([key, value, mono]) => {dl.append(node("dt", "", key), node("dd", mono ? "mono" : "", value ?? "—"));});
    return dl;
  }
  function card(title, ...children) {return append(node("section", "panel detail-card"), node("h2", "small-heading", title), children);}
  function readResult(results, key) {const item = results[key]; return item?.status === "fulfilled" ? item.value : {items: [], unavailable: item?.reason};}
  async function loadJob(routeKey) {
    if (!state.jobId) throw new Error("Select a valid job.");
    const result = await api("/jobs/" + encodeURIComponent(state.jobId));
    if (location.hash !== routeKey) return;
    state.job = result.job || result;
    $("page-title").textContent = name(state.job);
    const endpoint = "/jobs/" + encodeURIComponent(state.jobId);
    const keys = ["attempts", "events", "artifacts"];
    if (actions(state.job).includes("manage_members")) keys.push("members");
    const values = await Promise.allSettled(keys.map((key) => api(endpoint + "/" + key + (key === "events" ? "?limit=30" : ""))));
    if (location.hash !== routeKey) return;
    state.supplemental = Object.fromEntries(keys.map((key, i) => [key, values[i]]));
    renderDetail();
    if (state.tab === "logs") await loadLogs(false);
  }
  function renderDetail() {
    const job = state.job;
    const wrap = $("detail-panel"); wrap.replaceChildren();
    const banner = node("div", "detail-banner");
    append(banner, append(node("div", "meta"), node("span", "job-name", name(job)), node("span", "secondary mono", identity(job))), badge(job.state), progress(job));
    wrap.append(banner);
    const nav = node("div", "detail-nav");
    [["overview", "Overview"], ["logs", "Logs"], ["artifacts", "Artifacts"]].concat(actions(job).includes("manage_members") ? [["access", "Access"]] : []).forEach(([tab, label]) => {
      const link = node("a", "button small" + (tab === state.tab ? " active" : ""), label);
      link.href = "#job/" + encodeURIComponent(identity(job)) + "?tab=" + tab;
      if (tab === state.tab) link.setAttribute("aria-current", "page");
      nav.append(link);
    });
    const controls = node("div", "detail-actions");
    ["cancel", "retry", "reconcile", "purge"].filter((action) => actions(job).includes(action)).forEach((action) => controls.append(button(human(action), () => showAction(action), "small " + (action === "cancel" || action === "purge" ? "danger" : ""))));
    nav.append(controls); wrap.append(nav);
    if (state.tab === "overview") renderOverview(wrap);
    else if (state.tab === "logs") renderLogs(wrap);
    else if (state.tab === "artifacts") renderArtifacts(wrap);
    else if (state.tab === "access" && actions(job).includes("manage_members")) renderMembers(wrap);
    else wrap.append(empty("View unavailable", "Your current role does not permit this view."));
  }
  function renderOverview(wrap) {
    const job = state.job, input = spec(job), grid = node("div", "detail-grid");
    const [current, target] = roundValues(job);
    const values = [["Job ID", identity(job), true], ["Project", input.project_id || job.project_id], ["Phase", job.phase ? human(job.phase) : "—"], ["Created", when(job.created_at, true)], ["First started", when(job.first_reserved_at || job.started_at, true)], ["Deadline", when(job.deadline_at || job.deadline, true)], ["Final round", current + " / " + target], ["Attempt", job.attempt_number ?? job.current_attempt ?? "—"], ["Cleanup", human(job.cleanup_status || job.retention?.cleanup_status || "pending")]];
    if (String(job.state).toUpperCase() === "QUEUED") values.push(["Resource wait", elapsed(job.queued_at || job.created_at)], ["Queue reason", queueReason(job)]);
    if (job.error_code || job.failure_reason) values.push(["Failure reason", human(job.error_code || job.failure_reason)]);
    grid.append(card("Lifecycle", keyValues(values)));
    const sourceValues = [["Source", input.source_id], ["Exact commit", input.source_commit, true], ["Runtime", input.runtime_image, true], ["Plugin", input.plugin, true], ["Space", job.space_id, true], ["Spec hash", job.spec_hash, true]];
    const sourceCard = card("Source and provenance", keyValues(sourceValues));
    if (input.options && Object.keys(input.options).length) sourceCard.append(node("h3", "", "Plugin options"), node("pre", "preformatted", JSON.stringify(input.options, null, 2)));
    grid.append(sourceCard);
    const components = input.components || [];
    const resourcesCard = card("Resource requests", components.length ? components.map((component) => append(node("div", "resource-note"), node("h3", "", human(component.role) + " · " + component.component_id), keyValues([["Pool", component.resources?.pool_id], ["CPU", Number(component.resources?.cpu_millicores || 0) / 1000 + " cores"], ["Memory", bytes(component.resources?.memory_bytes)], ["Scratch", bytes(component.resources?.disk_bytes)], ["Profile", component.resources?.sandbox_profile], ["GPU", component.resources?.gpu_count || "None"]]))): node("p", "muted", "Resource requests are not yet reported."));
    grid.append(resourcesCard);
    const participantCard = card("Participants and readiness");
    const participants = job.participants || input.participants || [];
    if (!participants.length) participantCard.append(node("p", "muted", "No participant bindings recorded."));
    else {
      const table = node("table"), head = node("tr"); ["Participant", "Mode", "Readiness", "Enrollment"].forEach((h) => head.append(node("th", "", h))); table.append(append(node("thead"), head));
      const body = node("tbody");
      participants.forEach((p) => {
        const participantId = p.participant_id || p.id;
        const enrollment = p.enrollment || state.enrollments[identity(job) + ":" + participantId];
        const cell = node("td");
        if (p.mode === "external") {
          cell.append(node("span", "secondary", enrollment?.status ? human(enrollment.status) : "Not yet checked"));
          cell.append(button("Check status", () => checkEnrollment(p), "small quiet"));
          const approvedNode = participantNode(p);
          const canEnroll = (actions(job).includes("enroll_participant") || ["operator", "admin"].includes(job.role)) && ["QUEUED", "PROVISIONING", "STARTING", "RUNNING"].includes(job.state);
          if (canEnroll && approvedNode && !enrollment?.status?.match(/^(enrolled|running|training|publishing|completed)$/)) cell.append(button("Enroll", () => showAction("enroll_participant", {...p, node_id: approvedNode}), "small"));
        } else cell.append(node("span", "muted", "Managed allocation"));
        body.append(append(node("tr"), node("td", "mono", participantId), node("td", "", human(p.mode || "external")), node("td", "", p.readiness || p.status ? human(p.readiness || p.status) : "Not reported"), cell));
      });
      table.append(body); participantCard.append(append(node("div", "table-scroll"), table));
    }
    grid.append(participantCard);
    const metrics = job.metrics || job.progress?.metrics || {};
    const metricEntries = Array.isArray(metrics) ? metrics.map((m) => [m.name || m.key, m.value]) : Object.entries(metrics);
    if (metricEntries.length) {
      const metricGrid = node("div", "metrics");
      metricEntries.forEach(([label, value]) => metricGrid.append(append(node("div", "metric"), node("div", "metric-label", human(label)), node("div", "metric-value", typeof value === "number" ? value.toLocaleString(undefined, {maximumFractionDigits: 5}) : String(value)))));
      grid.append(card("Latest metrics", metricGrid));
    }
    const attempts = readResult(state.supplemental, "attempts");
    const attemptsCard = card("Execution attempts");
    if (attempts.unavailable) attemptsCard.append(node("p", "muted", errorMessage(attempts.unavailable)));
    else if (!list(attempts).length) attemptsCard.append(node("p", "muted", "No execution attempts yet. A queued job begins its first attempt after admission."));
    else {
      const table = node("table"), head = node("tr"); ["Attempt", "State", "Started", "Outcome"].forEach((h) => head.append(node("th", "", h))); table.append(append(node("thead"), head));
      const body = node("tbody");
      list(attempts).forEach((a) => body.append(append(node("tr"), node("td", "mono", a.number ?? a.attempt_number ?? a.id ?? a.attempt_id), append(node("td"), badge(a.state || a.status || "pending")), node("td", "", when(a.started_at || a.created_at)), node("td", "", a.error_code || a.failure_code || a.outcome || "—"))));
      table.append(body); attemptsCard.append(append(node("div", "table-scroll"), table));
    }
    grid.append(attemptsCard);
    const events = readResult(state.supplemental, "events");
    const timelineCard = card("Job timeline"); timelineCard.classList.add("full");
    if (events.unavailable) timelineCard.append(node("p", "muted", errorMessage(events.unavailable)));
    else if (!list(events).length) timelineCard.append(node("p", "muted", "No lifecycle events recorded."));
    else {
      const timeline = node("ol", "timeline");
      list(events).forEach((event) => {
        const detail = event.detail || event.data || event.payload;
        timeline.append(append(node("li"), node("div", "timeline-title", human(event.kind || event.type || event.event || "update")), node("time", "timeline-time", when(event.created_at || event.timestamp, true)), detail ? node("p", "timeline-detail", typeof detail === "string" ? detail : JSON.stringify(detail)) : null));
      }); timelineCard.append(timeline);
      if (events.next_cursor) timelineCard.append(button("Load more events", async () => {
        try {
          const more = await api("/jobs/" + encodeURIComponent(identity(state.job)) + "/events?" + query({limit: 100, cursor: events.next_cursor}));
          state.supplemental.events = {status: "fulfilled", value: {items: list(events).concat(list(more)).slice(-1000), next_cursor: more.next_cursor}};
          renderDetail();
        } catch (error) {notice("page-error", errorMessage(error));}
      }, "small"));
    }
    grid.append(timelineCard);
    const expires = job.artifacts_expires_at || job.expires_at || job.retention?.expires_at;
    const retentionCard = card("Retention", node("p", "muted", "Lifecycle history and access checks remain available after artifacts expire."), keyValues([["Artifacts expire", when(expires, true)], ["Retention", (job.retention_days ?? job.retention?.days ?? 90) + " days after termination"], ["Cleanup", human(job.cleanup_status || job.retention?.cleanup_status || "pending")]]));
    grid.append(retentionCard); wrap.append(grid);
  }
  function renderLogs(wrap) {
    const panel = card("Execution logs");
    const toolbar = node("div", "log-toolbar");
    const component = node("select"); component.id = "log-component"; const all = node("option", "", "All components"); all.value = ""; component.append(all);
    (spec(state.job).components || []).forEach((c) => {const o = node("option", "", c.component_id); o.value = c.component_id; component.append(o);});
    const attempt = node("select"); attempt.id = "log-attempt"; const every = node("option", "", "All attempts"); every.value = ""; attempt.append(every);
    list(readResult(state.supplemental, "attempts")).forEach((a) => {const o = node("option", "", "Attempt " + (a.number ?? a.attempt_number ?? a.id)); o.value = a.number || a.attempt_number; attempt.append(o);});
    component.value = state.logComponent || ""; attempt.value = state.logAttempt || "";
    append(toolbar, append(node("label"), node("span", "", "Component"), component), append(node("label"), node("span", "", "Attempt"), attempt), button("Load logs", () => {state.logCursor = null; state.logs = []; loadLogs(false).catch((e) => notice("page-error", errorMessage(e)));}, "small"));
    panel.append(toolbar);
    const output = node("pre", "log-output", "Loading logs…"); output.id = "log-output"; output.setAttribute("aria-label", "Execution log output"); panel.append(output);
    const controls = node("div", "log-page-controls");
    const loadMore = button("Load more", () => {state.logCursor = state.logNext; loadLogs(true).catch((e) => notice("page-error", errorMessage(e)));}, "small"); loadMore.id = "load-more-logs"; loadMore.disabled = true;
    controls.append(node("span", "muted", "Logs are bounded and rendered as plain text."), loadMore); panel.append(controls); wrap.append(panel);
  }
  async function loadLogs(more) {
    if (state.tab !== "logs" || !state.job) return;
    const id = identity(state.job);
    state.logComponent = $("log-component")?.value || ""; state.logAttempt = $("log-attempt")?.value || "";
    const result = await api("/jobs/" + encodeURIComponent(id) + "/logs?" + query({limit: 100, cursor: state.logCursor, component: $("log-component")?.value, attempt: $("log-attempt")?.value}));
    if (state.jobId !== id || state.tab !== "logs") return;
    const entries = list(result).map((line) => typeof line === "string" ? line : [line.created_at || line.timestamp ? "[" + when(line.created_at || line.timestamp) + "]" : "", line.component_id || line.component ? (line.component_id || line.component) + ":" : "", line.expired ? "[Expired under retention policy]" : line.data ?? line.text ?? line.message ?? line.line ?? ""].filter(Boolean).join(" "));
    state.logs = more ? state.logs.concat(entries).slice(-2000) : entries;
    state.logNext = result.next_cursor || null;
    $("log-output").textContent = state.logs.length ? state.logs.join("\n") : (result.expired ? "These logs have expired under the retention policy." : "No logs are available for this selection.");
    $("load-more-logs").disabled = !state.logNext;
  }
  function safeDownload(value) {
    if (typeof value !== "string") return null;
    try {const parsed = new URL(value, location.origin); return parsed.origin === location.origin && parsed.pathname.startsWith("/api/") ? parsed.href : null;} catch (_) {return null;}
  }
  async function downloadArtifact(artifact) {
    const id = artifact.id || artifact.artifact_id;
    const result = await api("/jobs/" + encodeURIComponent(identity(state.job)) + "/artifacts/" + encodeURIComponent(id));
    const url = safeDownload(result.download_url || result.url || result.broker_url || (result.download_available ? BASE + "/jobs/" + encodeURIComponent(identity(state.job)) + "/artifacts/" + encodeURIComponent(id) + "/download" : null));
    if (!url) throw new Error("The download broker is unavailable for this artifact. Its retained metadata remains visible.");
    const a = node("a"); a.href = url; a.download = artifact.name || artifact.filename || id; a.rel = "noopener"; document.body.append(a); a.click(); a.remove();
  }
  function renderArtifacts(wrap) {
    const result = readResult(state.supplemental, "artifacts"), panel = card("Retained artifacts");
    panel.append(node("p", "muted", "Downloads are authorized by the manager and served as attachments. Expired data retains its provenance."));
    if (result.unavailable) panel.append(node("p", "muted", errorMessage(result.unavailable)));
    else if (!list(result).length) panel.append(empty("No retained artifacts", "Checkpoints and output metadata appear here as the job produces them."));
    else {
      const table = node("table"), head = node("tr"); ["Artifact", "Size", "Provenance", "Retention", ""].forEach((h) => head.append(node("th", "", h))); table.append(append(node("thead"), head)); const body = node("tbody");
      list(result).forEach((artifact) => {
        const expired = artifact.expired || artifact.status === "expired" || ["expired", "deleted", "deleting"].includes(artifact.state) || artifact.expires_at && new Date(artifact.expires_at).valueOf() < Date.now();
        const control = expired ? node("span", "muted", "Expired") : artifact.download_available === false ? node("span", "muted", "Unavailable") : button("Download", () => downloadArtifact(artifact).catch((e) => notice("page-error", errorMessage(e))), "small");
        body.append(append(node("tr"), append(node("td"), node("span", "job-name", artifact.name || artifact.filename || artifact.id), node("span", "secondary", human(artifact.kind || "artifact"))), node("td", "", bytes(artifact.size_bytes ?? artifact.size)), node("td", "mono", artifact.sha256 || artifact.digest || "—"), node("td", "", when(artifact.expires_at)), append(node("td"), control)));
      }); table.append(body); panel.append(append(node("div", "table-scroll"), table));
    }
if (result.next_cursor) panel.append(button("Load more artifacts", async () => {
      try {
        const more = await api("/jobs/" + encodeURIComponent(identity(state.job)) + "/artifacts?" + query({limit: 100, cursor: result.next_cursor}));
        state.supplemental.artifacts = {status: "fulfilled", value: {items: list(result).concat(list(more)).slice(-1000), next_cursor: more.next_cursor}};
        renderDetail();
      } catch (error) {notice("page-error", errorMessage(error));}
    }, "small"));
    wrap.append(panel);
  }
  function participantNode(participant) {
    if (participant.node_id) return participant.node_id;
    return (state.catalog?.participant_bindings || []).find((binding) => binding.id === participant.dataset_binding && binding.participant_id === participant.participant_id)?.node_id;
  }
  async function checkEnrollment(participant) {
    const jobId = identity(state.job), participantId = participant.participant_id || participant.id;
    try {
      const result = await api("/jobs/" + encodeURIComponent(jobId) + "/participants/" + encodeURIComponent(participantId) + "/enrollment");
      state.enrollments[jobId + ":" + participantId] = result;
    } catch (error) {
      if (error.status === 404 && error.code === "participant_enrollment_not_found") state.enrollments[jobId + ":" + participantId] = {status: "not_enrolled"};
      else {notice("page-error", errorMessage(error)); return;}
    }
    renderDetail();
  }
  function renderMembers(wrap) {
    const panel = card("Job access"), result = readResult(state.supplemental, "members");
    panel.append(node("p", "muted", "Membership applies to this job, including its history, logs, and artifacts. Keep at least one administrator."));
    panel.append(button("Grant access", () => {notice("member-error", ""); $("member-form").reset(); state.memberKey = uuid(); state.memberJob = {...state.job}; $("member-dialog").showModal();}, "small"));
    if (result.unavailable) panel.append(node("p", "muted", errorMessage(result.unavailable)));
    else {
      const table = node("table"), head = node("tr"); ["Principal", "Role", "Actions"].forEach((h) => head.append(node("th", "", h))); table.append(append(node("thead"), head)); const body = node("tbody");
      list(result).forEach((member) => {
        const id = member.principal_id || member.id;
        const edit = button("Edit", () => {notice("member-error", ""); $("member-form").elements.principal_id.value = id; $("member-form").elements.role.value = member.role; state.memberKey = uuid(); state.memberJob = {...state.job}; $("member-dialog").showModal();}, "small");
        const remove = button("Revoke", () => showAction("remove_member", member), "small remove-button");
        body.append(append(node("tr"), node("td", "mono", id), node("td", "", human(member.role)), append(node("td"), append(node("div", "flex-row"), edit, remove))));
      }); table.append(body); panel.append(append(node("div", "table-scroll"), table));
    }
    wrap.append(panel);
  }
  async function loadOperations() {
    if (!operator()) throw new Error("Platform operator access is required.");
    const result = await api("/pools"); const pools = list(result); const container = $("operations-panel"); container.replaceChildren();
    container.append(node("p", "operator-intro muted", "Operational inventory does not grant access to job code, logs, or artifacts. Unqualified or quarantined pools cannot run workloads."));
    if (!pools.length) {container.append(empty("No resource pools", "Register and qualify a resource pool before admitting jobs.")); return;}
    const grid = node("div", "pool-grid");
    pools.forEach((pool) => {
      const capacity = pool.capacity || pool, used = pool.reserved || pool.used || pool.allocated || {};
      const health = pool.quarantined ? "quarantined" : pool.healthy === false ? "unhealthy" : "healthy";
      const item = card(pool.name || pool.id || pool.pool_id);
      item.append(append(node("div", "health-row"), node("span", "mono", pool.id || pool.pool_id), badge(health)));
      const resources = node("div", "pool-resources");
      [["CPU", (Number(used.cpu_millicores || 0) / 1000) + " / " + (Number(capacity.cpu_millicores || 0) / 1000) + " cores"], ["Memory", bytes(used.memory_bytes || 0) + " / " + bytes(capacity.memory_bytes)], ["Storage", bytes(used.disk_bytes || 0) + " / " + bytes(capacity.disk_bytes)]].forEach(([label, value]) => resources.append(append(node("div", "pool-resource"), node("span", "", label), node("strong", "", value))));
      item.append(resources, keyValues([["Node", pool.node_id], ["Sandbox profiles", (pool.qualified_profiles || pool.profiles || pool.sandbox_profiles || []).join(", ") || "None"], ["GPU capacity", (capacity.gpu_uuids || capacity.gpu_ids || []).length], ["Last heartbeat", when(pool.last_heartbeat_at)], ["Quarantine reason", pool.quarantine_reason || "—"]]));
      if (pool.cleanup_status || pool.cleanup_pending !== undefined) item.append(node("p", "retention-note", "Cleanup: " + human(pool.cleanup_status || "pending") + (pool.cleanup_pending !== undefined ? " · " + pool.cleanup_pending + " pending operations" : "")));
      grid.append(item);
    }); container.append(grid);
    if (result.cleanup) container.append(card("Cleanup health", node("pre", "preformatted", JSON.stringify(result.cleanup, null, 2))));
  }
  function showAction(action, member = null) {
    state.action = {name: action, job: {...state.job}, key: uuid(), member};
    const descriptions = {
      cancel: "Cancel this job. The manager fences new writes, stops its components, and confirms termination before releasing resources. History remains available.",
      retry: "Request a new attempt with this job's unchanged specification and original deadline. Uncertain publication outcomes must be reconciled first.",
      reconcile: "Submit explicit verified evidence to resolve an uncertain execution or publication outcome.",
      purge: "Authorize deletion of this terminal job's retained resources. The manager preserves an audit tombstone and confirms ownership before cleanup.",
      remove_member: "Revoke " + (member?.principal_id || member?.id || "") + "'s access to this job. Their future requests and streams will be denied.",
      enroll_participant: "Enroll this external participant on its approved node. Its dataset remains local, and its assignment is bound to this job and attempt."
    };
    $("action-title").textContent = action === "remove_member" ? "Revoke access" : action === "enroll_participant" ? "Enroll participant" : human(action) + " job";
    $("action-description").textContent = descriptions[action];
    $("action-form").reset(); notice("action-error", "");
    $("reconcile-fields").hidden = action !== "reconcile"; $("purge-fields").hidden = action !== "purge";
    $("reconcile-fields").querySelectorAll("input,select").forEach((field) => {field.disabled = action !== "reconcile"; field.required = action === "reconcile";});
    $("enroll-fields").hidden = action !== "enroll_participant";
    $("action-form").elements.enrollment_node.value = action === "enroll_participant" ? member.node_id : "";
    $("submit-action").textContent = action === "remove_member" ? "Revoke access" : action === "enroll_participant" ? "Enroll participant" : human(action);
    $("submit-action").className = "button " + (["cancel", "purge", "remove_member"].includes(action) ? "danger" : "primary");
    $("action-dialog").showModal();
  }
  async function submitAction(event) {
    event.preventDefault();
    const action = state.action;
    if (!action) return;
    notice("action-error", ""); $("submit-action").disabled = true;
    try {
      if (action.name === "purge" && $("action-form").elements.confirmation.value !== identity(action.job)) throw new Error("Enter the exact job ID to authorize purge.");
      let body;
      if (action.name === "reconcile") {
        const fields = $("action-form").elements;
        body = {evidence: {publication_id: fields.publication_id.value.trim(), outcome: fields.publication_outcome.value, evidence_ref: fields.evidence_ref.value.trim()}};
      }
      if (action.name === "enroll_participant") body = {node_id: $("action-form").elements.enrollment_node.value};
      const endpoint = "/jobs/" + encodeURIComponent(identity(action.job)) + (action.name === "remove_member" ? "/members/" + encodeURIComponent(action.member.principal_id || action.member.id) : action.name === "enroll_participant" ? "/participants/" + encodeURIComponent(action.member.participant_id || action.member.id) + "/enroll" : "/" + action.name);
      await api(endpoint, {method: action.name === "remove_member" ? "DELETE" : "POST", body, job: action.job, key: action.key});
      if (action.name === "enroll_participant") state.enrollments[identity(action.job) + ":" + action.member.participant_id] = {status: "enrolled", node_id: body.node_id};
      $("action-dialog").close(); toast(action.name === "remove_member" ? "Access revoked." : human(action.name) + " accepted."); await refresh();
    } catch (error) {notice("action-error", errorMessage(error));}
    finally {$("submit-action").disabled = false;}
  }
  function parseObject(value, label) {
    let parsed; try {parsed = JSON.parse(value);} catch (_) {throw new Error(label + " must be valid JSON.");}
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error(label + " must be a JSON object.");
    return parsed;
  }
  function selectOptions(element, entries, getId, getLabel, placeholder) {
    const first = node("option", "", placeholder); first.value = ""; element.replaceChildren(first);
    entries.forEach((entry) => {const option = node("option", "", getLabel(entry)); option.value = getId(entry); element.append(option);});
  }
  async function openCreate() {
    notice("create-error", ""); $("create-form").reset(); state.createRequest = null;
    try {
      state.catalog = await api("/catalog");
      const projects = state.catalog.projects || [];
      if (!projects.length) throw new Error("You need project submission access before creating a job.");
      selectOptions($("create-project"), projects, (p) => p.id || p.project_id, (p) => p.name || p.id, "Select a project");
      if (projects.length === 1) $("create-project").value = projects[0].id || projects[0].project_id;
      selectOptions($("create-image"), state.catalog.runtime_images || state.catalog.images || [], (i) => i.id || i.digest, (i) => i.name || i.id || i.digest, "Select an approved runtime");
      const pools = (state.catalog.pools || []).filter((p) => (p.profiles || p.qualified_profiles || p.sandbox_profiles || []).includes("runsc-cpu-v1"));
      selectOptions($("create-pool"), pools, (p) => p.id || p.pool_id, (p) => p.name || p.id, "Select an approved CPU pool");
      updateProjectFields();
      $("create-dialog").showModal();
    } catch (error) {notice("page-error", errorMessage(error));}
  }
  function resourceInputs(container, poolEntries, prefix) {
    const grid = node("div", "form-grid"); grid.hidden = true;
    const fields = [["pool", "Participant pool", "select", ""], ["cpu", "CPU (millicores)", "number", "1000"], ["memory", "Memory (MiB)", "number", "2048"], ["disk", "Scratch (MiB)", "number", "4096"]];
    fields.forEach(([key, label, type, value]) => {
      const input = type === "select" ? node("select") : node("input");
      input.dataset.resource = key; input.name = prefix + "_" + key;
      if (type === "select") selectOptions(input, poolEntries, (p) => p.id || p.pool_id, (p) => p.name || p.id, "Select participant pool");
      else {input.type = type; input.value = value; input.min = "1"; input.step = "1";}
      grid.append(append(node("label"), node("span", "", label), input));
    });
    container.append(grid); return grid;
  }
  function updateProjectFields() {
    if (!state.catalog) return;
    const project = $("create-project").value;
    selectOptions($("create-image"), (state.catalog.runtime_images || state.catalog.images || []).filter((image) => !image.project_id || image.project_id === project), (image) => image.id || image.digest, (image) => image.name || image.id || image.digest, "Select an approved runtime");
    const sources = (state.catalog.sources || []).filter((s) => !s.project_id || s.project_id === project);
    selectOptions($("create-source"), sources, (s) => s.id || s.source_id, (s) => s.name || s.id, "Select an approved source");
    const bindingList = $("participant-bindings"); bindingList.replaceChildren();
    const bindings = (state.catalog.participant_bindings || []).filter((b) => !b.project_id || b.project_id === project);
    const pools = (state.catalog.pools || []).filter((p) => (p.profiles || p.qualified_profiles || p.sandbox_profiles || []).includes("runsc-cpu-v1"));
    if (!bindings.length) bindingList.append(node("p", "muted", "No approved participant bindings are configured for this project."));
    bindings.forEach((binding, index) => {
      const block = node("div", "binding-block"); block.dataset.bindingIndex = String(index);
      const check = node("input"); check.type = "checkbox"; check.value = binding.id || binding.dataset_binding; check.dataset.participant = binding.participant_id;
      const label = append(node("label", "binding-option"), check, append(node("span"), node("span", "", binding.participant_id), node("span", "secondary", binding.dataset_label || binding.id)));
      const mode = node("select"); mode.setAttribute("aria-label", "Execution mode for " + binding.participant_id); mode.dataset.mode = "true";
      [["external", "External participant"], ["managed", "Managed participant"]].forEach(([v, l]) => {const o = node("option", "", l); o.value = v; if (v === "managed" && !pools.length) o.disabled = true; mode.append(o);});
      block.append(label, mode);
      const resourceGrid = resourceInputs(block, pools, "participant_" + index);
      const update = () => {mode.disabled = !check.checked; resourceGrid.hidden = !(check.checked && mode.value === "managed"); resourceGrid.querySelectorAll("input,select").forEach((input) => {input.disabled = resourceGrid.hidden; input.required = !resourceGrid.hidden;});};
      check.addEventListener("change", update); mode.addEventListener("change", update); update();
      bindingList.append(block);
    });
  }
  function positive(value, label) {const number = Number(value); if (!Number.isSafeInteger(number) || number < 1) throw new Error(label + " must be a positive whole number."); return number;}
  function requestResources(pool, cpu, memory, disk) {
    if (!pool) throw new Error("Select an approved resource pool.");
    return {pool_id: pool, cpu_millicores: positive(cpu, "CPU"), memory_bytes: positive(memory, "Memory") * 1048576, disk_bytes: positive(disk, "Storage") * 1048576, gpu_count: 0, gpu_profile: null, sandbox_profile: "runsc-cpu-v1"};
  }
  function creationSpec() {
    const form = $("create-form").elements;
    const components = [{component_id: "owner", role: "owner", participant_id: null, resources: requestResources(form.pool_id.value, form.cpu_millicores.value, form.memory_mib.value, form.disk_mib.value)}];
    const participants = [];
    $("participant-bindings").querySelectorAll(".binding-block").forEach((block) => {
      const check = block.querySelector('input[type="checkbox"]'); if (!check.checked) return;
      const mode = block.querySelector("[data-mode]").value; const component = mode === "managed" ? "participant-" + block.dataset.bindingIndex : null;
      if (participants.some((participant) => participant.participant_id === check.dataset.participant)) throw new Error("Select one dataset binding per participant.");
      participants.push({participant_id: check.dataset.participant, dataset_binding: check.value, mode, component_id: component});
      if (component) {
        const read = (field) => block.querySelector('[data-resource="' + field + '"]').value;
        components.push({component_id: component, role: "participant", participant_id: check.dataset.participant, resources: requestResources(read("pool"), read("cpu"), read("memory"), read("disk"))});
      }
    });
    const secretRefs = form.secret_refs ? parseObject(form.secret_refs.value, "Secret references") : {};
    return {project_id: form.project_id.value, name: form.display_name.value.trim(), source_id: form.source_id.value, source_commit: form.source_commit.value.trim(), runtime_image: form.runtime_image.value, plugin: form.plugin.value.trim(), options: parseObject(form.plugin_options.value, "Plugin options"), secret_refs: secretRefs, participants, components, target_round: positive(form.target_final_round.value, "Final round"), max_duration_seconds: positive(form.max_duration_minutes.value, "Duration") * 60};
  }
  async function submitCreate(event) {
    event.preventDefault(); notice("create-error", ""); $("submit-create").disabled = true;
    try {
      const body = creationSpec(), encoded = JSON.stringify(body);
      if (!state.createRequest || state.createRequest.body !== encoded) state.createRequest = {body: encoded, key: uuid()};
      const result = await api("/jobs", {method: "POST", body, key: state.createRequest.key});
      const job = result.job || result;
      $("create-dialog").close(); toast("Job created and queued for resources."); location.hash = "#job/" + encodeURIComponent(identity(job));
    } catch (error) {notice("create-error", errorMessage(error));}
    finally {$("submit-create").disabled = false;}
  }
  async function submitMember(event) {
    event.preventDefault(); notice("member-error", ""); $("submit-member").disabled = true;
    try {
      const fields = $("member-form").elements;
      const encoded = JSON.stringify([fields.principal_id.value.trim(), fields.role.value]);
      if (state.memberBody !== encoded) {state.memberKey = uuid(); state.memberBody = encoded;}
      await api("/jobs/" + encodeURIComponent(identity(state.memberJob)) + "/members/" + encodeURIComponent(fields.principal_id.value.trim()), {method: "PUT", body: {role: fields.role.value}, key: state.memberKey, job: state.memberJob});
      $("member-dialog").close(); toast("Job access saved."); await refresh();
    } catch (error) {notice("member-error", errorMessage(error));}
    finally {$("submit-member").disabled = false;}
  }
  async function initialize() {
    try {
      const info = await api("/session"); state.session = info;
      state.authenticated = info.authenticated !== false && !!info.principal;
      $("login-link").href = info.login_url === "/auth/login" ? info.login_url : "/auth/login";
      if (!state.authenticated) {$("login-panel").hidden = false; connection("Sign in required", false); return;}
      $("application").hidden = false; $("login-panel").hidden = true;
      $("identity").textContent = info.principal.display_name || info.principal.principal_id;
      $("logout-button").hidden = false; $("operations-link").hidden = !operator();
      const catalog = await api("/catalog"); state.catalog = catalog;
      $("create-button").hidden = !(catalog.projects || []).length;
      // Initial routing closes dialogs; finish it before accepting creation.
      route(); $("create-button").disabled = false; connectEvents();
    } catch (error) {
      $("login-panel").hidden = false;
      $("login-panel").querySelector("p").textContent = errorMessage(error);
      connection("Connection unavailable", false);
    }
  }
  $("refresh-button").addEventListener("click", refresh);
  $("create-button").addEventListener("click", openCreate);
  $("create-project").addEventListener("change", updateProjectFields);
  $("create-form").addEventListener("submit", submitCreate);
  $("action-form").addEventListener("submit", submitAction);
  $("member-form").addEventListener("submit", submitMember);
  document.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => $(b.dataset.close).close()));
  $("job-search").addEventListener("input", () => {state.search = $("job-search").value; resetPagination(); scheduleRefresh();});
  $("state-filter").addEventListener("change", () => {state.filter = $("state-filter").value; resetPagination(); refresh();});
  $("next-page").addEventListener("click", () => {if (!state.next) return; state.previous.push(state.cursor); state.cursor = state.next; state.page++; refresh();});
  $("previous-page").addEventListener("click", () => {if (!state.previous.length) return; state.cursor = state.previous.pop(); state.page--; refresh();});
  $("logout-button").addEventListener("click", async () => {try {await api("/auth/logout", {method: "POST"}); expireSession(); $("login-panel").querySelector("p").textContent = "You have signed out. Sign in to retrieve current job authorization.";} catch (error) {notice("page-error", errorMessage(error));}});
  window.addEventListener("hashchange", route);
  document.addEventListener("visibilitychange", () => {if (!document.hidden && state.authenticated) refresh();});
  setInterval(() => {if (state.authenticated && !document.hidden && (!state.streamLive || state.view === "operations")) refresh();}, 10000);
  // Revalidate the session even while SSE is healthy; identity checks stay server-side.
  setInterval(async () => {if (!state.authenticated) return; try {const session = await api("/session"); if (!session.authenticated) expireSession(); else state.session = session;} catch (error) {if (error.status === 401) expireSession();}}, 60000);
  initialize();
})();
