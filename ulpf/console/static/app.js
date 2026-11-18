// ULPF SOC Console — zero-dependency single-page app (air-gapped: no CDN, no build step).
// All dynamic text goes through textContent (never innerHTML), so event data cannot inject markup.

const $ = (s, r = document) => r.querySelector(s);
const store = {
  get(k, d = null) { try { return sessionStorage.getItem(k) ?? localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v, persist = false) { try { (persist ? localStorage : sessionStorage).setItem(k, v); } catch {} },
};
const state = { me: null, tenant: store.get("ulpf.tenant", ""), ws: null, subs: new Set(), metrics: [], view: null };

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "style") Object.assign(el.style, v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c instanceof Node ? c : String(c));
  return el;
}
const fmt = {
  n: (v) => (v == null ? "—" : Number(v).toLocaleString(undefined, { maximumFractionDigits: 1 })),
  bytes: (v) => { if (!v) return "0 B/s"; const u = ["B", "KB", "MB", "GB"]; let i = 0; while (v >= 1024 && i < 3) { v /= 1024; i++; } return `${v.toFixed(1)} ${u[i]}/s`; },
  dur: (s) => { if (s == null) return "—"; s = Math.round(s); if (s < 90) return `${s}s`; if (s < 5400) return `${Math.round(s / 60)}m`; if (s < 172800) return `${(s / 3600).toFixed(1)}h`; return `${(s / 86400).toFixed(1)}d`; },
  t: (v) => { if (!v) return "—"; const d = typeof v === "number" ? new Date(v * 1000) : new Date(v); return isNaN(d) ? String(v) : d.toLocaleString(); },
};
function toast(msg, bad = false) {
  const t = $("#toast"); t.textContent = msg; t.style.borderColor = bad ? "var(--bad)" : "var(--line)";
  t.classList.add("show"); clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("show"), 4200);
}
async function api(path, { method = "GET", body, raw = false } = {}) {
  const headers = {};
  const key = store.get("ulpf.key"); if (key) headers["X-API-Key"] = key;
  if (state.tenant) headers["X-ULPF-Tenant"] = state.tenant;
  if (body !== undefined && !(body instanceof Blob)) headers["Content-Type"] = "application/json";
  const r = await fetch(path, { method, headers, body: body === undefined ? undefined : body instanceof Blob ? body : JSON.stringify(body) });
  if (raw) { if (!r.ok) throw new Error(`${r.status} ${r.statusText}`); return r; }
  let data = null; try { data = await r.json(); } catch {}
  if (!r.ok) { const m = (data && (data.detail || data.error)) || `${r.status} ${r.statusText}`; throw new Error(typeof m === "string" ? m : JSON.stringify(m)); }
  return data;
}
const can = (p) => !!state.me && state.me.permissions.includes(p);
const sev = (s) => h("span", { class: `sev ${s || "low"}` }, s || "low");
function card(title, ...kids) { return h("section", { class: "card", "aria-label": title }, h("h2", {}, title), ...kids); }
function table(cols, rows, onRow) {
  if (!rows.length) return h("div", { class: "empty" }, "No data");
  return h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, cols.map((c) => h("th", { scope: "col" }, c[0])))),
    h("tbody", {}, rows.map((r) => { const tr = h("tr", onRow ? { tabindex: "0", onclick: () => onRow(r), onkeydown: (e) => e.key === "Enter" && onRow(r) } : {}, cols.map((c) => h("td", {}, c[1](r)))); return tr; }))));
}
function dialog(title, body) {
  const d = $("#dlg"); const b = $("#dlg-body"); b.replaceChildren(h("h2", {}, title), body); d.showModal();
}

// ---------------------------------------------------------------- live stream
async function connect() {
  if (state.ws) try { state.ws.close(); } catch {}
  const live = $("#live");
  try {
    const { ticket } = await api("/api/v1/console/ws-ticket", { method: "POST" });
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${location.host}/api/v1/console/stream?ticket=${encodeURIComponent(ticket)}&tenant=${encodeURIComponent(state.tenant)}`);
    state.ws = ws;
    ws.onopen = () => { live.textContent = "● live"; live.classList.add("on"); connect.delay = 1000; };
    ws.onmessage = (m) => { let msg; try { msg = JSON.parse(m.data); } catch { return; }
      if (msg.type === "metrics") { state.metrics.push(msg.data); if (state.metrics.length > 600) state.metrics.shift(); }
      if (msg.type === "case" && msg.data.event === "created") toast(`New case: ${msg.data.title}`);
      if (msg.type === "approval") toast(`Approval requested: ${msg.data.summary}`);
      state.subs.forEach((fn) => { try { fn(msg); } catch (e) { console.error(e); } }); };
    ws.onclose = () => { live.textContent = "● reconnecting"; live.classList.remove("on");
      connect.delay = Math.min((connect.delay || 1000) * 2, 30000); setTimeout(connect, connect.delay); };
  } catch (e) { live.textContent = "● offline"; setTimeout(connect, 10000); }
}
function subscribe(fn) { state.subs.add(fn); return () => state.subs.delete(fn); }

// ---------------------------------------------------------------- charts
function sparkline(canvas, values, color = "#4f8cff") {
  const dpr = devicePixelRatio || 1, w = canvas.clientWidth || 300, hgt = canvas.clientHeight || 80;
  canvas.width = w * dpr; canvas.height = hgt * dpr; const c = canvas.getContext("2d"); c.scale(dpr, dpr);
  c.clearRect(0, 0, w, hgt); if (values.length < 2) return;
  const max = Math.max(1, ...values); c.beginPath();
  values.forEach((v, i) => { const x = (i / (values.length - 1)) * w, y = hgt - 4 - (v / max) * (hgt - 12); i ? c.lineTo(x, y) : c.moveTo(x, y); });
  c.strokeStyle = color; c.lineWidth = 2; c.stroke(); c.lineTo(w, hgt); c.lineTo(0, hgt); c.closePath();
  c.fillStyle = color + "22"; c.fill();
  c.fillStyle = getComputedStyle(document.body).getPropertyValue("--muted"); c.font = "11px system-ui"; c.fillText(`max ${fmt.n(max)}`, 6, 12);
}
function bars(canvas, labels, values, color = "#4f8cff") {
  const dpr = devicePixelRatio || 1, w = canvas.clientWidth || 600, hgt = canvas.clientHeight || 140;
  canvas.width = w * dpr; canvas.height = hgt * dpr; const c = canvas.getContext("2d"); c.scale(dpr, dpr); c.clearRect(0, 0, w, hgt);
  const max = Math.max(1, ...values), bw = w / Math.max(1, values.length);
  values.forEach((v, i) => { const bh = (v / max) * (hgt - 20); c.fillStyle = color; c.fillRect(i * bw + 1, hgt - 14 - bh, Math.max(1, bw - 2), bh); });
  c.fillStyle = getComputedStyle(document.body).getPropertyValue("--muted"); c.font = "10px system-ui";
  if (labels.length) { c.fillText(String(labels[0]).slice(0, 19), 2, hgt - 2); const l = String(labels[labels.length - 1]).slice(0, 19); c.fillText(l, w - c.measureText(l).width - 2, hgt - 2); }
}
function gauge(ratio) { const g = h("div", { class: `gauge ${ratio > 0.9 ? "bad" : ratio > 0.7 ? "warn" : ""}`, role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": String(Math.round(ratio * 100)) }, h("i")); g.firstChild.style.width = `${Math.min(100, ratio * 100)}%`; return g; }

// ---------------------------------------------------------------- views
const views = {};

views.cockpit = async (main) => {
  const o = await api("/api/v1/console/overview");
  const m = o.metrics || {};
  const eps = h("div", { class: "v" }, fmt.n(m.eps)), bw = h("div", { class: "v" }, fmt.bytes(m.bytes_per_s));
  const fillV = h("div", { class: "v" }, `${Math.round((m.buffer_fill || 0) * 100)}%`); let fillG = gauge(m.buffer_fill || 0);
  const drops = h("div", { class: "v" }, fmt.n(m.dropped));
  const k = o.incidents || {};
  const fillCard = h("div", { class: "card kpi" }, h("h2", {}, "Buffer fill"), fillV, fillG);
  main.append(h("div", { class: "grid kpis" },
    h("div", { class: "card kpi" }, h("h2", {}, "Events / s"), eps, h("div", { class: "s" }, `node ${o.node || "standalone"}`)),
    h("div", { class: "card kpi" }, h("h2", {}, "Ingest bandwidth"), bw, h("div", { class: "s" }, `${fmt.n(m.records)} records journaled`)),
    fillCard,
    h("div", { class: "card kpi" }, h("h2", {}, "Dropped"), drops, h("div", { class: "s" }, "events dropped by full buffers")),
    h("div", { class: "card kpi" }, h("h2", {}, "Open cases"), h("div", { class: "v" }, fmt.n((o.open_cases || []).length)), h("div", { class: "s" }, `${fmt.n(k.sla_breached)} SLA breaches (30d)`)),
    h("div", { class: "card kpi" }, h("h2", {}, "MTTD / MTTR"), h("div", { class: "v" }, `${fmt.dur(k.mttd_seconds)} / ${fmt.dur(k.mttr_seconds)}`), h("div", { class: "s" }, "30-day averages"))));
  const spark = h("canvas", { height: "90", "aria-label": "Events per second, live" });
  const feed = h("ul", { class: "feed", "aria-live": "polite" });
  const addFeed = (c, live) => feed.prepend(h("li", {}, sev(c.severity), h("a", { href: `#/cases?open=${encodeURIComponent(c.id)}` }, c.title), h("span", { class: "muted" }, live ? "just now" : fmt.t(c.updated_at || c.created_at))));
  (o.open_cases || []).slice().reverse().forEach((c) => addFeed(c));
  const appr = h("div"), detBody = h("tbody");
  const addDet = (d) => { detBody.prepend(h("tr", {}, h("td", {}, fmt.t(d.timestamp)), h("td", {}, d.title), h("td", {}, sev(d.level)), h("td", {}, (d.techniques || []).join(", "))));
    while (detBody.children.length > 100) detBody.lastChild.remove(); };
  (o.detections || []).slice().reverse().forEach(addDet);
  const renderApprovals = (list) => appr.replaceChildren(list.length ? table([["Requested", (a) => fmt.t(a.requested_at)], ["Action", (a) => a.summary], ["Decide", (a) => h("div", { class: "row" },
    h("button", { class: "ok", disabled: !can("approvals:decide"), onclick: () => decide(a, true) }, "Approve"),
    h("button", { class: "danger", disabled: !can("approvals:decide"), onclick: () => decide(a, false) }, "Reject"))]], list) : h("div", { class: "empty" }, "No pending approvals"));
  async function decide(a, ok) {
    const reason = prompt(ok ? "Approval reason" : "Rejection reason") ?? "";
    try { await api(`/api/v1/soar/approvals/${a.id}`, { method: "POST", body: { approve: ok, reason } }); toast(ok ? "Approved" : "Rejected"); refreshApprovals(); }
    catch (e) { toast(e.message, true); }
  }
  async function refreshApprovals() { try { renderApprovals((await api("/api/v1/soar/approvals")).approvals); } catch { renderApprovals([]); } }
  renderApprovals(o.approvals || []);
  main.append(h("div", { class: "grid cols-2" }, card("Live ingestion (events / s)", spark), card("High-severity incident feed", feed)));
  main.append(h("div", { class: "grid cols-even" }, card("Containment approvals (human in the loop)", appr),
    card("Detections (live)", h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Rule", "Level", "ATT&CK"].map((c) => h("th", { scope: "col" }, c)))), detBody)))));
  state.metrics = (o.history || []).concat(state.metrics.slice(-1));
  sparkline(spark, state.metrics.map((x) => x.eps));
  state.unsub = subscribe((msg) => {
    if (msg.type === "metrics") { const d = msg.data; eps.textContent = fmt.n(d.eps); bw.textContent = fmt.bytes(d.bytes_per_s); drops.textContent = fmt.n(d.dropped);
      fillV.textContent = `${Math.round(d.buffer_fill * 100)}%`; const g = gauge(d.buffer_fill); fillG.replaceWith(g); fillG = g; sparkline(spark, state.metrics.map((x) => x.eps)); }
    if (msg.type === "case" && msg.data.event === "created" && ["high", "critical"].includes(msg.data.severity)) addFeed(msg.data, true);
    if (msg.type === "approval") refreshApprovals();
    if (msg.type === "detection") addDet(msg.data);
  });
};

// ---- Investigate: multi-tab query editor
const KEYWORDS = { kql: /\b(where|summarize|project|extend|by|top|take|sort|count|distinct|bin|ago|has|contains|startswith|endswith|and|or|not|in|between|asc|desc|join|on|make-series|mv-expand)\b/g,
  spl: /\b(search|where|stats|count|by|sort|head|tail|table|fields|rex|eval|timechart|bin|span|dedup|rename|top|rare|AND|OR|NOT|as|dc)\b/g,
  hql: /\b(groupBy|count|sort|head|tail|timeChart|select|table|regex|eval|in|top|sum|avg|max|min|limit|field|distinct|and|or|not)\b/g };
function highlight(text, dialect) {
  const frag = document.createDocumentFragment(); const re = new RegExp(`("(?:[^"\\\\]|\\\\.)*"|'(?:[^'\\\\]|\\\\.)*')|(\\b\\d+(?:\\.\\d+)?[smhd]?\\b)|${KEYWORDS[dialect].source}|([|=<>!~]+)`, "g");
  let last = 0, m;
  while ((m = re.exec(text))) { if (m.index > last) frag.append(text.slice(last, m.index));
    const cls = m[1] ? "tk-s" : m[2] ? "tk-n" : m[3] ? "tk-k" : "tk-o"; frag.append(h("span", { class: cls }, m[0])); last = re.lastIndex; if (m[0] === "") re.lastIndex++; }
  frag.append(text.slice(last) + "\n"); return frag;
}
let schemaCache = null;
views.investigate = async (main) => {
  schemaCache = schemaCache || await api("/api/v1/console/schema").catch(() => ({ columns: [], nested: [], dialects: { kql: [], spl: [], hql: [] } }));
  const tabs = JSON.parse(store.get("ulpf.tabs", "null") || "null") || [{ name: "Query 1", dialect: "kql", text: "events\n| where timestamp > ago(1h)\n| summarize count() by category\n| sort by count_ desc" }];
  let cur = 0;
  const tabBar = h("div", { class: "tabs", role: "tablist" });
  const dialect = h("select", { "aria-label": "Query language" }, ["kql", "spl", "hql"].map((d) => h("option", { value: d }, d === "spl" ? "SPL2" : d.toUpperCase())));
  const ta = h("textarea", { spellcheck: "false", "aria-label": "Query editor", autocomplete: "off" });
  const pre = h("pre", { "aria-hidden": "true" });
  const ac = h("div", { class: "ac", role: "listbox", hidden: true });
  const editor = h("div", { class: "editor" }, pre, ta, ac);
  const results = h("div"), hist = h("canvas", { height: "140", "aria-label": "Events over time" }), meta = h("div", { class: "muted" });
  const save = () => { tabs[cur].text = ta.value; tabs[cur].dialect = dialect.value; store.set("ulpf.tabs", JSON.stringify(tabs), true); };
  const paint = () => pre.replaceChildren(highlight(ta.value, dialect.value));
  const drawTabs = () => tabBar.replaceChildren(...tabs.map((t, i) => h("button", { role: "tab", "aria-selected": String(i === cur), onclick: () => { save(); cur = i; load(); } }, t.name)),
    h("button", { "aria-label": "New tab", onclick: () => { save(); tabs.push({ name: `Query ${tabs.length + 1}`, dialect: "kql", text: "events\n| take 100" }); cur = tabs.length - 1; load(); } }, "+"));
  const load = () => { ta.value = tabs[cur].text; dialect.value = tabs[cur].dialect; paint(); drawTabs(); };
  ta.addEventListener("input", () => { paint(); save(); suggest(); });
  ta.addEventListener("scroll", () => { pre.scrollTop = ta.scrollTop; });
  dialect.addEventListener("change", () => { paint(); save(); });
  let acItems = [], acSel = 0;
  function suggest() {
    const upto = ta.value.slice(0, ta.selectionStart); const m = upto.match(/[A-Za-z_][\w.]*$/);
    if (!m || m[0].length < 2) { ac.hidden = true; return; }
    const words = [...schemaCache.columns, ...schemaCache.nested, ...(schemaCache.dialects[dialect.value] || [])];
    acItems = [...new Set(words)].filter((w) => w.toLowerCase().startsWith(m[0].toLowerCase()) && w !== m[0]).slice(0, 12);
    if (!acItems.length) { ac.hidden = true; return; }
    acSel = 0; ac.replaceChildren(...acItems.map((w, i) => h("div", { role: "option", "aria-selected": String(i === 0), onmousedown: (e) => { e.preventDefault(); accept(w); } }, w)));
    const lines = upto.split("\n"); ac.style.top = `${Math.min(lines.length * 19.5 + 12, 220)}px`; ac.style.left = `${Math.min(lines.at(-1).length * 7.8, 500)}px`; ac.hidden = false;
  }
  function accept(w) { const pos = ta.selectionStart; const upto = ta.value.slice(0, pos).replace(/[A-Za-z_][\w.]*$/, w);
    ta.value = upto + ta.value.slice(pos); ta.selectionStart = ta.selectionEnd = upto.length; ac.hidden = true; paint(); save(); ta.focus(); }
  ta.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); return; }
    if (ac.hidden) return;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); acSel = (acSel + (e.key === "ArrowDown" ? 1 : acItems.length - 1)) % acItems.length;
      [...ac.children].forEach((c, i) => c.setAttribute("aria-selected", String(i === acSel))); }
    else if (e.key === "Tab" || e.key === "Enter") { e.preventDefault(); accept(acItems[acSel]); }
    else if (e.key === "Escape") ac.hidden = true;
  });
  async function run() {
    save(); results.replaceChildren(h("div", { class: "empty" }, "Running…")); const t0 = performance.now();
    try {
      const r = await api("/api/v1/query", { method: "POST", body: { dialect: dialect.value, query: ta.value, max_rows: 2000 } });
      const rows = r.rows || [], cols = (r.columns || []).map((c) => c.name || c);
      meta.textContent = `${fmt.n(rows.length)} rows · ${Math.round(performance.now() - t0)} ms${r.truncated ? " · truncated" : ""}`;
      results.replaceChildren(table(cols.map((c) => [c, (row) => { const v = row[c]; return typeof v === "object" && v !== null ? JSON.stringify(v).slice(0, 120) : String(v ?? ""); }]), rows, inspect));
      const tcol = cols.find((c) => /time|timestamp|bin/.test(c)); const ncol = cols.find((c) => /count/.test(c));
      if (tcol && ncol) bars(hist, rows.map((x) => x[tcol]), rows.map((x) => Number(x[ncol]) || 0)); else hist.getContext("2d").clearRect(0, 0, hist.width, hist.height);
    } catch (e) { meta.textContent = ""; results.replaceChildren(h("div", { class: "empty", role: "alert" }, e.message)); }
  }
  function inspect(row) { dialog("Event inspector", h("div", { class: "json" }, JSON.stringify(row, null, 2))); }
  const ask = h("input", { placeholder: "Ask the copilot: e.g. top 10 source ips with failed logins in the last 24 hours", "aria-label": "Ask the copilot", style: { flex: "1" } });
  const askBtn = h("button", { onclick: async () => {
    if (!ask.value.trim()) return;
    try { const r = await api("/api/v1/copilot/nl2query", { method: "POST", body: { question: ask.value, language: dialect.value } });
      ta.value = r.query; paint(); save(); toast(`${r.valid ? "Valid" : "Unverified"} ${r.language.toUpperCase()} (${r.origin}): ${r.explanation}`, !r.valid); }
    catch (e) { toast(e.message, true); } } }, "Ask copilot");
  const explorer = h("div", { class: "scroll" }, h("table", {}, h("tbody", {}, [...schemaCache.columns, ...schemaCache.nested].map((f) =>
    h("tr", {}, h("td", { class: "mono" }, h("button", { class: "btn", title: `Insert ${f}`, onclick: () => { const p = ta.selectionStart; ta.value = ta.value.slice(0, p) + f + ta.value.slice(p); paint(); save(); ta.focus(); } }, f)))))));
  main.append(h("div", { class: "grid cols-2" },
    h("div", { class: "card" }, tabBar, h("div", { class: "row", style: { margin: "10px 0" } }, dialect, ask, askBtn), editor,
      h("div", { class: "row", style: { marginTop: "10px" } }, h("button", { class: "primary", onclick: run, disabled: !can("query:run") }, "Run (Ctrl+Enter)"), meta)),
    card("Schema explorer", explorer)));
  main.append(card("Histogram", hist), card("Results", results));
  load();
};

// ---- Cases board
const LANES = ["new", "triaged", "investigating", "containment", "eradication", "closed", "post_incident"];
views.cases = async (main, params) => {
  const top = h("div", { class: "row" },
    h("button", { class: "primary", disabled: !can("cases:write"), onclick: newCase }, "New case"),
    h("span", { class: "muted" }, "Drag a card to another column to move it through the incident lifecycle."));
  const board = h("div", { class: "board", role: "list" });
  main.append(top, board);
  const drawer = h("aside", { class: "drawer", "aria-label": "Case details" }); document.body.append(drawer);
  state.cleanup = () => drawer.remove();
  async function refresh() {
    let cases = []; try { cases = (await api("/api/v1/soar/cases?limit=500")).cases; } catch (e) { board.replaceChildren(h("div", { class: "empty" }, e.message)); return; }
    board.replaceChildren(...LANES.map((lane) => {
      const items = cases.filter((c) => c.state === lane);
      const el = h("section", { class: "lane", role: "listitem", "aria-label": lane, dataset: { lane } }, h("h3", {}, lane.replace("_", " "), h("span", {}, String(items.length))),
        items.map((c) => h("article", { class: "case-card", draggable: "true", tabindex: "0", dataset: { id: c.id },
          ondragstart: (e) => e.dataTransfer.setData("text/plain", c.id), onclick: () => open(c.id), onkeydown: (e) => e.key === "Enter" && open(c.id) },
          h("div", { class: "row" }, sev(c.severity), (c.sla?.breached || []).length ? h("span", { class: "pill", title: "SLA breached" }, "SLA") : null),
          h("div", { class: "t" }, c.title), h("div", { class: "muted" }, `${c.id} · ${c.assignee || "unassigned"}`))));
      el.addEventListener("dragover", (e) => { e.preventDefault(); el.classList.add("drop"); });
      el.addEventListener("dragleave", () => el.classList.remove("drop"));
      el.addEventListener("drop", async (e) => { e.preventDefault(); el.classList.remove("drop"); const id = e.dataTransfer.getData("text/plain");
        try { await api(`/api/v1/soar/cases/${id}`, { method: "PATCH", body: { state: lane } }); toast(`${id} → ${lane}`); refresh(); } catch (err) { toast(err.message, true); } });
      return el; }));
  }
  async function newCase() {
    const title = prompt("Case title"); if (!title) return;
    const severity = prompt("Severity (low, medium, high, critical)", "medium") || "medium";
    try { const c = await api("/api/v1/soar/cases", { method: "POST", body: { title, severity } }); toast(`Created ${c.id}`); refresh(); } catch (e) { toast(e.message, true); }
  }
  async function open(id) {
    let c; try { c = await api(`/api/v1/soar/cases/${id}`); } catch (e) { toast(e.message, true); return; }
    let pbs = []; try { pbs = (await api("/api/v1/soar/playbooks")).playbooks; } catch {}
    const note = h("textarea", { rows: "3", "aria-label": "Add a note", style: { width: "100%" } });
    const pbSel = h("select", { "aria-label": "Playbook" }, pbs.map((p) => h("option", { value: p.id }, p.name)));
    const dry = h("input", { type: "checkbox", id: "dry", checked: true });
    const inputs = h("input", { placeholder: '{"ip": "203.0.113.5"}', "aria-label": "Playbook inputs (JSON)", style: { flex: "1" }, value: JSON.stringify(c.entities || {}) });
    const triageOut = h("div");
    drawer.replaceChildren(
      h("div", { class: "row" }, h("button", { onclick: () => drawer.classList.remove("open"), "aria-label": "Close" }, "✕"), sev(c.severity), h("strong", {}, c.id)),
      h("h2", {}, c.title), h("p", { class: "muted" }, c.description || ""),
      h("div", { class: "grid kpis" },
        h("div", { class: "card kpi" }, h("h2", {}, "State"), h("div", { class: "v" }, c.state)),
        h("div", { class: "card kpi" }, h("h2", {}, "MTTD"), h("div", { class: "v" }, fmt.dur(c.mttd_seconds))),
        h("div", { class: "card kpi" }, h("h2", {}, "Contain"), h("div", { class: "v" }, fmt.dur(c.time_to_contain_seconds))),
        h("div", { class: "card kpi" }, h("h2", {}, "SLA"), h("div", { class: "v" }, (c.sla.breached || []).join(", ") || "ok"))),
      card("ATT&CK", h("div", {}, (c.mitre || []).map((t) => h("span", { class: "pill" }, t)))),
      card("Containment & playbooks", h("div", { class: "row" }, pbSel, inputs, h("label", { for: "dry" }, dry, " dry run"),
        h("button", { class: "primary", disabled: !can("playbooks:run"), onclick: async () => {
          let inp = {}; try { inp = JSON.parse(inputs.value || "{}"); } catch { toast("Inputs must be JSON", true); return; }
          try { const r = await api(`/api/v1/soar/playbooks/${pbSel.value}/run`, { method: "POST", body: { case_id: c.id, inputs: inp, dry_run: dry.checked } });
            toast(`Run ${r.id}: ${r.status}`); setTimeout(() => open(id), 800); } catch (e) { toast(e.message, true); } } }, "Run")),
        table([["Run", (r) => r.id], ["Playbook", (r) => r.playbook], ["Status", (r) => r.status], ["", (r) => h("button", { disabled: !can("playbooks:run"), onclick: async () => {
          if (!confirm(`Roll back every containment action of ${r.id}?`)) return;
          try { const res = await api(`/api/v1/soar/runs/${r.id}/rollback`, { method: "POST", body: {} }); toast(`Rolled back ${res.rolled_back.length} action(s)`); } catch (e) { toast(e.message, true); } } }, "Roll back")]], c.runs || [])),
      card("Copilot triage", h("button", { disabled: !can("copilot:use"), onclick: async () => {
        triageOut.replaceChildren(h("div", { class: "empty" }, "Investigating…"));
        try { const t = await api("/api/v1/copilot/triage", { method: "POST", body: { case_id: c.id } });
          triageOut.replaceChildren(h("p", {}, h("strong", {}, `${t.verdict} (confidence ${t.confidence}) — `), t.summary), h("p", {}, h("strong", {}, "Root cause: "), t.root_cause || "—"),
            table([["Stage", (r) => r.stage], ["Recommendation", (r) => `${r.kind}: ${r.recommendation}`], ["Target", (r) => r.target || ""]], t.recommendations || []));
        } catch (e) { triageOut.replaceChildren(h("div", { class: "empty" }, e.message)); } } }, "Investigate with copilot"), triageOut),
      card("Timeline", h("ol", { class: "timeline" }, (c.timeline || []).map((t) => h("li", {}, h("div", { class: "muted" }, `${fmt.t(t.at)} · ${t.actor}`), h("div", {}, `${t.kind}: ${JSON.stringify(t.detail).slice(0, 300)}`))))),
      card("Notes", note, h("button", { disabled: !can("cases:write"), onclick: async () => { if (!note.value.trim()) return;
        try { await api(`/api/v1/soar/cases/${c.id}/notes`, { method: "POST", body: { text: note.value } }); open(id); } catch (e) { toast(e.message, true); } } }, "Add note")),
      card("Evidence locker", table([["Artifact", (a) => a.id], ["Kind", (a) => a.kind], ["Name", (a) => a.name || ""], ["SHA-256", (a) => h("span", { class: "mono" }, a.sha256.slice(0, 16) + "…")], ["Bytes", (a) => fmt.n(a.bytes)]], c.artifacts || [])),
      card("Tasks", table([["Task", (t) => t.title], ["Status", (t) => t.status], ["Assignee", (t) => t.assignee || ""]], c.tasks || [])));
    drawer.classList.add("open"); drawer.focus?.();
  }
  await refresh();
  if (params.get("open")) open(params.get("open"));
  state.unsub = subscribe((m) => { if (m.type === "case") refresh(); });
};

// ---- ATT&CK heat map
views.attack = async (main) => {
  const r = await api("/api/v1/console/attack");
  const max = Math.max(1, ...r.tactics.flatMap((t) => t.techniques.map((x) => x.count)));
  main.append(h("p", { class: "muted" }, `${fmt.n(r.total)} technique observations from detections and cases. Darker cells have more activity.`),
    h("div", { class: "matrix", role: "table", "aria-label": "MITRE ATT&CK Enterprise matrix" }, r.tactics.map((t) => h("div", { class: "tac", role: "rowgroup" },
      h("h3", { role: "columnheader" }, t.name, h("br"), h("span", { class: "muted" }, t.id)),
      t.techniques.map((x) => { const el = h("div", { class: "tech", role: "cell", title: `${x.id} ${x.name}: ${x.count}` }, h("strong", {}, x.id), " ", x.name, x.count ? h("span", { class: "pill" }, String(x.count)) : null);
        if (x.count) { const a = 0.15 + 0.75 * (x.count / max); el.style.background = `rgba(240, 82, 82, ${a.toFixed(2)})`; el.style.color = a > 0.5 ? "#fff" : ""; } return el; })))));
};

// ---- Graph & flows
views.graph = async (main) => {
  const hours = h("select", { "aria-label": "Time window" }, [1, 24, 168, 720].map((x) => h("option", { value: String(x), selected: x === 24 }, x < 24 ? `${x}h` : `${x / 24}d`)));
  const g = h("div", { class: "card" }), s = h("div", { class: "card" });
  main.append(h("div", { class: "row" }, h("label", {}, "Window ", hours)), h("div", { class: "grid cols-even" }, g, s));
  const NS = "http://www.w3.org/2000/svg", svg = (t, a = {}) => { const e = document.createElementNS(NS, t); for (const [k, v] of Object.entries(a)) e.setAttribute(k, v); return e; };
  async function draw() {
    const [gr, fl] = await Promise.all([api(`/api/v1/console/graph?hours=${hours.value}`).catch(() => ({ nodes: [], edges: [] })), api(`/api/v1/console/flows?hours=${hours.value}`).catch(() => ({ flows: [] }))]);
    // identity / lateral movement: force-directed layout
    const W = 640, H = 480, nodes = gr.nodes.slice(0, 200).map((n, i) => ({ ...n, x: W / 2 + Math.cos(i) * 150, y: H / 2 + Math.sin(i) * 150, vx: 0, vy: 0 }));
    const idx = Object.fromEntries(nodes.map((n, i) => [n.id, i])); const edges = gr.edges.filter((e) => e.source in idx && e.target in idx);
    for (let it = 0; it < 220; it++) {
      for (const a of nodes) for (const b of nodes) { if (a === b) continue; const dx = a.x - b.x, dy = a.y - b.y, d2 = Math.max(50, dx * dx + dy * dy); a.vx += dx / d2 * 120; a.vy += dy / d2 * 120; }
      for (const e of edges) { const a = nodes[idx[e.source]], b = nodes[idx[e.target]]; const dx = b.x - a.x, dy = b.y - a.y; a.vx += dx * 0.004; a.vy += dy * 0.004; b.vx -= dx * 0.004; b.vy -= dy * 0.004; }
      for (const n of nodes) { n.vx += (W / 2 - n.x) * 0.002; n.vy += (H / 2 - n.y) * 0.002; n.x = Math.max(20, Math.min(W - 20, n.x + n.vx)); n.y = Math.max(20, Math.min(H - 20, n.y + n.vy)); n.vx *= 0.6; n.vy *= 0.6; }
    }
    const sv = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Identity and lateral movement graph" });
    for (const e of edges) { const a = nodes[idx[e.source]], b = nodes[idx[e.target]];
      const l = svg("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: e.failed ? "#f05252" : e.kind === "uses" ? "#93a0bd" : "#4f8cff", "stroke-width": String(Math.min(6, 1 + Math.log2(1 + e.count))), "stroke-opacity": ".6" });
      const t = svg("title"); t.textContent = `${e.source} → ${e.target}: ${e.count}${e.failed ? ` (${e.failed} failed)` : ""}${e.user ? ` as ${e.user}` : ""}`; l.append(t); sv.append(l); }
    for (const n of nodes) { const c = svg("circle", { cx: n.x, cy: n.y, r: String(Math.min(14, 4 + Math.log2(1 + n.weight))), fill: n.kind === "user" ? "#f5a524" : "#2fbf71" });
      const t = svg("title"); t.textContent = `${n.label || n.id} (${n.weight})`; c.append(t); sv.append(c);
      const lb = svg("text", { x: n.x + 8, y: n.y - 8, "font-size": "10", fill: "currentColor" }); lb.textContent = (n.label || n.id).slice(0, 24); sv.append(lb); }
    g.replaceChildren(h("h2", {}, "Identity & lateral movement"), nodes.length ? sv : h("div", { class: "empty" }, "No authentication activity in this window"),
      h("p", { class: "muted" }, "Orange: users · green: hosts · red edges: failed authentications"));
    // Sankey: source -> port -> action
    const flows = fl.flows; const cols = [[...new Set(flows.map((f) => f.source))], [...new Set(flows.map((f) => f.port))], [...new Set(flows.map((f) => f.action))]];
    const total = flows.reduce((a, f) => a + f.count, 0) || 1, SW = 640, SH = 480, colX = [20, 300, 560];
    const pos = cols.map((col, ci) => { let y = 10; const out = {}; const sums = col.map((k) => flows.filter((f) => [f.source, f.port, f.action][ci] === k).reduce((a, f) => a + f.count, 0));
      col.forEach((k, i) => { const hgt = Math.max(3, (sums[i] / total) * (SH - 20 - col.length * 4)); out[k] = { y, h: hgt, off: 0, off2: 0 }; y += hgt + 4; }); return out; });
    const sk = svg("svg", { viewBox: `0 0 ${SW} ${SH}`, role: "img", "aria-label": "Flows from sources to ports to actions" });
    flows.forEach((f) => { const w = Math.max(1, (f.count / total) * (SH - 60)); const s1 = pos[0][f.source], p1 = pos[1][f.port], a1 = pos[2][f.action];
      const y0 = s1.y + s1.off + w / 2, y1 = p1.y + p1.off + w / 2, y2 = p1.y + p1.off2 + w / 2, y3 = a1.y + a1.off + w / 2; s1.off += w; p1.off += w; p1.off2 += w; a1.off += w;
      for (const [xa, ya, xb, yb] of [[colX[0] + 10, y0, colX[1], y1], [colX[1] + 10, y2, colX[2], y3]]) {
        const p = svg("path", { d: `M${xa},${ya} C${(xa + xb) / 2},${ya} ${(xa + xb) / 2},${yb} ${xb},${yb}`, stroke: /denied|blocked|dropped|failed/.test(f.action) ? "#f05252" : "#4f8cff", "stroke-opacity": ".35", "stroke-width": String(w), fill: "none" });
        const t = svg("title"); t.textContent = `${f.source} → :${f.port} → ${f.action} (${f.count})`; p.append(t); sk.append(p); } });
    cols.forEach((col, ci) => col.forEach((k) => { const p = pos[ci][k]; sk.append(svg("rect", { x: colX[ci], y: p.y, width: "10", height: String(p.h), fill: "#93a0bd" }));
      const lb = svg("text", { x: ci === 2 ? colX[ci] - 6 : colX[ci] + 14, y: p.y + p.h / 2 + 3, "font-size": "10", fill: "currentColor", "text-anchor": ci === 2 ? "end" : "start" }); lb.textContent = ci === 1 ? `:${k}` : k; sk.append(lb); }));
    s.replaceChildren(h("h2", {}, "Network flows (source → port → action)"), flows.length ? sk : h("div", { class: "empty" }, "No flows in this window"));
  }
  hours.addEventListener("change", draw); await draw();
};

// ---- Playbooks: visual DAG editor
views.playbooks = async (main) => {
  let data = { playbooks: [], errors: [] }; try { data = await api("/api/v1/soar/playbooks"); } catch (e) { main.append(h("div", { class: "empty" }, e.message)); return; }
  const sel = h("select", { "aria-label": "Playbook" }, h("option", { value: "" }, "— new playbook —"), data.playbooks.map((p) => h("option", { value: p.id }, `${p.name} (v${p.version})`)));
  const canvas = h("div", { class: "dag", "aria-label": "Playbook graph editor" }); const NS = "http://www.w3.org/2000/svg"; const lines = document.createElementNS(NS, "svg"); canvas.append(lines);
  const props = h("div"); let pb = { id: "new-playbook", name: "New playbook", version: 1, steps: [] }, selected = null, linking = null;
  const pos = {};
  function layout() { const depth = {}; const get = (s) => depth[s.id] ??= (s.needs || []).length ? 1 + Math.max(...s.needs.map((n) => get(pb.steps.find((x) => x.id === n) || { id: n, needs: [] }))) : 0;
    pb.steps.forEach(get); const per = {}; pb.steps.forEach((s) => { if (!pos[s.id]) { const d = depth[s.id]; per[d] = (per[d] || 0) + 1; pos[s.id] = { x: 20 + d * 190, y: 20 + (per[d] - 1) * 80 }; } }); }
  function draw() {
    canvas.querySelectorAll(".node").forEach((n) => n.remove()); lines.replaceChildren();
    for (const s of pb.steps) {
      const n = h("div", { class: `node${selected === s ? " sel" : ""}`, tabindex: "0", role: "button", "aria-label": `Step ${s.id}` }, h("div", { class: "h" }, s.id), h("div", { class: "k" }, s.type || (s.action ? `action: ${s.action}` : "step")),
        s.connector ? h("div", { class: "k" }, `⇢ ${s.connector}`) : null, h("span", { class: "port", title: "Drag to another step to make it depend on this one" }));
      n.style.left = `${pos[s.id].x}px`; n.style.top = `${pos[s.id].y}px`;
      n.addEventListener("pointerdown", (e) => { if (e.target.classList.contains("port")) { linking = s; e.stopPropagation(); return; } selected = s; edit(); const sx = e.clientX - pos[s.id].x, sy = e.clientY - pos[s.id].y;
        const mv = (ev) => { pos[s.id] = { x: Math.max(0, ev.clientX - sx), y: Math.max(0, ev.clientY - sy) }; n.style.left = `${pos[s.id].x}px`; n.style.top = `${pos[s.id].y}px`; wires(); };
        const up = () => { removeEventListener("pointermove", mv); removeEventListener("pointerup", up); draw(); }; addEventListener("pointermove", mv); addEventListener("pointerup", up); });
      n.addEventListener("pointerup", () => { if (linking && linking !== s) { s.needs = [...new Set([...(s.needs || []), linking.id])]; linking = null; draw(); } });
      n.addEventListener("keydown", (e) => { if (e.key === "Enter") { selected = s; edit(); } if (e.key === "Delete") { remove(s); } });
      canvas.append(n);
    }
    wires();
  }
  function wires() { lines.replaceChildren(); for (const s of pb.steps) for (const nd of s.needs || []) { const a = pos[nd], b = pos[s.id]; if (!a || !b) continue;
    const p = document.createElementNS(NS, "path"); p.setAttribute("d", `M${a.x + 160},${a.y + 22} C${a.x + 200},${a.y + 22} ${b.x - 40},${b.y + 22} ${b.x},${b.y + 22}`); p.setAttribute("stroke", "#4f8cff"); p.setAttribute("fill", "none"); p.setAttribute("stroke-width", "2"); lines.append(p); } }
  function remove(s) { pb.steps = pb.steps.filter((x) => x !== s); pb.steps.forEach((x) => x.needs = (x.needs || []).filter((n) => n !== s.id)); selected = null; edit(); draw(); }
  function edit() {
    if (!selected) { props.replaceChildren(h("p", { class: "muted" }, "Select a step to edit it. Drag the blue dot of a step onto another step to add a dependency.")); return; }
    const s = selected; const f = (k, label, ph = "") => { const i = h("input", { value: s[k] ?? "", placeholder: ph, "aria-label": label, style: { width: "100%" } }); i.addEventListener("change", () => { if (k === "id") { const old = s.id; pos[i.value] = pos[old]; pb.steps.forEach((x) => x.needs = (x.needs || []).map((n) => n === old ? i.value : n)); } s[k] = i.value || undefined; draw(); }); return h("label", {}, label, i); };
    const w = h("textarea", { rows: "5", "aria-label": "with (JSON)", style: { width: "100%" } }); w.value = JSON.stringify(s.with || {}, null, 1);
    w.addEventListener("change", () => { try { s.with = JSON.parse(w.value); w.style.borderColor = ""; } catch { w.style.borderColor = "var(--bad)"; } });
    props.replaceChildren(f("id", "Step id"), f("type", "Type", "action | condition | approval | foreach | playbook | set"), f("action", "Action", "block_ip, case.note…"), f("connector", "Connector", "perimeter-fw"),
      f("when", "When (expression)", "inputs.user"), f("if", "If (condition)"), h("label", {}, "with (JSON)", w),
      h("p", { class: "muted" }, `needs: ${(s.needs || []).join(", ") || "—"}`), h("div", { class: "row" }, h("button", { onclick: () => { s.needs = []; draw(); } }, "Clear dependencies"), h("button", { class: "danger", onclick: () => remove(s) }, "Delete step")));
  }
  const spec = () => ({ ...pb, steps: pb.steps.map((s) => Object.fromEntries(Object.entries(s).filter(([k, v]) => v !== undefined && !(Array.isArray(v) && !v.length) && !k.startsWith("_")))) });
  sel.addEventListener("change", () => { const p = data.playbooks.find((x) => x.id === sel.value); Object.keys(pos).forEach((k) => delete pos[k]);
    pb = p ? JSON.parse(JSON.stringify({ id: p.id, name: p.name, version: p.version, description: p.description, inputs: p.inputs, triggers: p.triggers, steps: p.steps })) : { id: "new-playbook", name: "New playbook", version: 1, steps: [] };
    selected = null; layout(); draw(); edit(); });
  const tools = h("div", { class: "row" }, sel,
    h("button", { onclick: () => { const id = `step${pb.steps.length + 1}`; const s = { id, action: "util.echo", needs: selected ? [selected.id] : [] }; pb.steps.push(s); layout(); selected = s; draw(); edit(); } }, "Add step"),
    h("button", { onclick: async () => { const r = await api("/api/v1/soar/playbooks/validate", { method: "POST", body: spec() }); toast(r.valid ? `Valid: ${r.steps} steps` : r.error, !r.valid); } }, "Validate"),
    h("button", { class: "primary", disabled: !can("playbooks:write"), onclick: async () => { pb.version = (pb.version || 0) + 1; try { await api("/api/v1/soar/playbooks", { method: "PUT", body: spec() }); toast(`Saved ${pb.id} v${pb.version}`); } catch (e) { toast(e.message, true); } } }, "Save"),
    h("button", { disabled: !can("playbooks:run"), onclick: async () => { try { const r = await api(`/api/v1/soar/playbooks/${pb.id}/run`, { method: "POST", body: { dry_run: true, inputs: {} } }); toast(`Dry run ${r.id}: ${r.status}`); } catch (e) { toast(e.message, true); } } }, "Dry run"),
    h("button", { onclick: () => dialog("Playbook JSON", h("div", { class: "json" }, JSON.stringify(spec(), null, 2))) }, "Export"));
  main.append(tools, data.errors?.length ? h("div", { class: "card" }, h("h2", {}, "Load errors"), data.errors.map((e) => h("div", { class: "muted" }, e))) : null,
    h("div", { class: "grid cols-2" }, canvas, card("Step properties", props)));
  edit(); layout(); draw();
};

// ---- Compliance
views.compliance = async (main) => {
  const fws = { cert_in: "CERT-In 2022", rbi_csf: "RBI CSF", sebi_cscrf: "SEBI CSCRF", soc2: "SOC 2 Type II", iso27001: "ISO 27001:2022", pci_dss_v4: "PCI DSS v4.0 Req 10" };
  const boxes = Object.entries(fws).map(([k, v]) => h("label", { class: "pill" }, h("input", { type: "checkbox", value: k, checked: true }), " ", v));
  const out = h("div"), org = h("input", { placeholder: "Organisation name", "aria-label": "Organisation" });
  const chosen = () => boxes.map((b) => b.querySelector("input")).filter((i) => i.checked).map((i) => i.value);
  main.append(h("div", { class: "card" }, h("h2", {}, "Frameworks"), h("div", { class: "row" }, boxes), h("div", { class: "row", style: { marginTop: "10px" } },
    h("button", { class: "primary", disabled: !can("compliance:read"), onclick: run }, "Collect evidence"), org,
    h("button", { disabled: !can("compliance:export"), onclick: exp }, "Export sealed bundle (ZIP)"))), out);
  async function run() { out.replaceChildren(h("div", { class: "empty" }, "Collecting evidence…"));
    try { const r = await api("/api/v1/compliance/matrix", { method: "POST", body: { frameworks: chosen() } });
      out.replaceChildren(...Object.values(r.frameworks).map((fw) => card(`${fw.name} — pass ${fw.summary.pass} · fail ${fw.summary.fail} · review ${fw.summary.review}`,
        table([["Control", (c) => c.id], ["Requirement", (c) => c.title], ["Status", (c) => h("span", { class: `status-${c.status}` }, c.status.toUpperCase())],
          ["Evidence", (c) => h("details", {}, h("summary", {}, "view"), h("div", { class: "json" }, JSON.stringify(c.evidence, null, 1).slice(0, 4000)))]], fw.controls)))); }
    catch (e) { out.replaceChildren(h("div", { class: "empty" }, e.message)); } }
  async function exp() { try { const r = await api("/api/v1/compliance/matrix/export", { method: "POST", body: { frameworks: chosen(), organisation: org.value }, raw: true });
    const blob = await r.blob(); const a = h("a", { href: URL.createObjectURL(blob), download: (r.headers.get("Content-Disposition") || "").split('"')[1] || "compliance.zip" }); document.body.append(a); a.click(); a.remove(); toast("Sealed bundle downloaded — verify with verify_pack.py"); }
    catch (e) { toast(e.message, true); } }
};

// ---- Fleet
views.fleet = async (main) => {
  let s, a; try { [s, a] = await Promise.all([api("/api/v1/fleet/summary"), api("/api/v1/fleet/agents")]); }
  catch (e) { main.append(h("div", { class: "card" }, h("h2", {}, "Fleet"), h("p", { class: "muted" }, `Fleet control plane not enabled (fleet.enabled: true) — ${e.message}`))); return; }
  main.append(h("div", { class: "grid kpis" }, h("div", { class: "card kpi" }, h("h2", {}, "Agents"), h("div", { class: "v" }, fmt.n(s.agents))),
    h("div", { class: "card kpi" }, h("h2", {}, "Online"), h("div", { class: "v" }, fmt.n(s.online))), h("div", { class: "card kpi" }, h("h2", {}, "Edge EPS"), h("div", { class: "v" }, fmt.n(s.eps))),
    h("div", { class: "card kpi" }, h("h2", {}, "Cluster buffer"), h("div", { class: "v" }, `${Math.round((s.cluster.buffer_fill || 0) * 100)}%`), gauge(s.cluster.buffer_fill || 0))),
    h("div", { class: "row" }, h("button", { class: "primary", disabled: !can("fleet:manage"), onclick: async () => { const group = prompt("Group", "default"); if (!group) return;
      const r = await api("/api/v1/fleet/tokens", { method: "POST", body: { group } }); dialog("Enrollment token (shown once)", h("div", { class: "json" }, `ulpf fleet agent --server ${location.origin} --enroll-token ${r.token} --id <agent-id>`)); } }, "New enrollment token")),
    card("Agents", table([["Agent", (x) => x.id], ["Group", (x) => x.group], ["Online", (x) => x.online ? "●" : "○"], ["EPS", (x) => fmt.n(x.stats?.eps)], ["Buffer", (x) => `${Math.round((x.stats?.buffer_fill || 0) * 100)}%`],
      ["Config", (x) => x.stats?.config_version ?? "—"], ["Cert expires", (x) => fmt.t(x.cert_expires)], ["", (x) => h("button", { class: "danger", disabled: !can("fleet:manage") || x.revoked, onclick: async () => { if (confirm(`Revoke ${x.id}?`)) { await api(`/api/v1/fleet/agents/${x.id}/revoke`, { method: "POST" }); route(); } } }, x.revoked ? "Revoked" : "Revoke")]], a.agents)));
};

// ---- Settings
views.settings = async (main) => {
  const key = h("input", { type: "password", value: store.get("ulpf.key") || "", "aria-label": "API key", style: { width: "420px" }, autocomplete: "off" });
  const remember = h("input", { type: "checkbox", id: "rem" });
  const theme = h("select", { "aria-label": "Theme" }, ["system", "dark", "light"].map((t) => h("option", { value: t, selected: (store.get("ulpf.theme") || "system") === t }, t)));
  theme.addEventListener("change", () => { store.set("ulpf.theme", theme.value, true); applyTheme(); });
  main.append(card("Authentication", h("p", { class: "muted" }, "Your API key is kept in this browser tab's session storage (or local storage if you choose to remember it). It is sent only to this server."),
    h("div", { class: "row" }, key, h("label", { for: "rem" }, remember, " remember on this device"), h("button", { class: "primary", onclick: async () => {
      try { sessionStorage.removeItem("ulpf.key"); localStorage.removeItem("ulpf.key"); } catch {} store.set("ulpf.key", key.value, remember.checked); await boot(); toast("Signed in"); } }, "Save"))),
    card("Appearance", h("label", {}, "Theme ", theme)),
    card("Session", h("div", { class: "json" }, JSON.stringify(state.me, null, 2))));
};

// ---- Live tail: queries evaluated on the stream as packets arrive (server-side, per ingest batch)
views.live = async (main) => {
  const dialect = h("select", { "aria-label": "Query language" }, ["kql", "spl", "hql"].map((d) => h("option", { value: d }, d === "spl" ? "SPL2" : d.toUpperCase())));
  const q = h("input", { value: store.get("ulpf.liveq") || "events | where severity >= 5", "aria-label": "Live query", style: { flex: "1", fontFamily: "var(--mono)" } });
  const startBtn = h("button", { class: "primary" }, "Start live tail"), stopBtn = h("button", { disabled: true }, "Stop");
  const stats = h("span", { class: "muted", "aria-live": "polite" }, "idle"), rate = h("canvas", { height: "70", "aria-label": "Matches per second" });
  const body = h("tbody"), head = h("thead"), MAX = 500;
  let tid = null, cols = null, running = false, total = 0; const perSec = [];
  async function loop() {
    let tick = Date.now(), inSec = 0;
    while (running && tid) {
      let r; try { r = await api(`/api/v1/live/${tid}?wait=5&max_rows=500`); } catch (e) { stats.textContent = e.message; break; }
      if (r.error) { stats.textContent = r.error; break; }
      const rows = r.rows || [];
      if (rows.length && !cols) { cols = Object.keys(rows[0]).filter((c) => !["normalised_json", "parsed_fields", "row_mac"].includes(c)).slice(0, 10);
        head.replaceChildren(h("tr", {}, cols.map((c) => h("th", { scope: "col" }, c)))); }
      for (const row of rows) { body.prepend(h("tr", { tabindex: "0", onclick: () => dialog("Event", h("div", { class: "json" }, JSON.stringify(row, null, 2))) },
        cols.map((c) => h("td", {}, typeof row[c] === "object" && row[c] !== null ? JSON.stringify(row[c]).slice(0, 100) : String(row[c] ?? "").slice(0, 160))))); }
      while (body.children.length > MAX) body.lastChild.remove();
      total += rows.length; inSec += rows.length;
      if (Date.now() - tick >= 1000) { perSec.push(inSec / ((Date.now() - tick) / 1000)); if (perSec.length > 120) perSec.shift(); tick = Date.now(); inSec = 0; sparkline(rate, perSec, "#2fbf71"); }
      stats.textContent = `${fmt.n(total)} matches · ${fmt.n(r.matched)} matched server-side · ${fmt.n(r.pending)} queued · ${fmt.n(r.dropped)} dropped`;
    }
  }
  async function stop() { running = false; startBtn.disabled = false; stopBtn.disabled = true; if (tid) { const t = tid; tid = null; try { await api(`/api/v1/live/${t}`, { method: "DELETE" }); } catch {} } }
  startBtn.onclick = async () => {
    store.set("ulpf.liveq", q.value, true); await stop(); body.replaceChildren(); cols = null; total = 0;
    try { const r = await api("/api/v1/live", { method: "POST", body: { dialect: dialect.value, query: q.value } }); tid = r.id; running = true;
      startBtn.disabled = true; stopBtn.disabled = false; stats.textContent = "waiting for matching events…"; loop(); }
    catch (e) { toast(e.message, true); }
  };
  stopBtn.onclick = stop;
  state.cleanup = stop;
  main.append(h("div", { class: "card" }, h("h2", {}, "Live tail — evaluated on the ingest stream, not on stored data"),
    h("div", { class: "row" }, dialect, q, startBtn, stopBtn), h("p", { class: "muted" }, "Filters run in the workers on every ingest batch (row-level KQL/SPL2/HQL: where / search / project). Up to 500 rows per batch are forwarded; the newest 500 are shown."), stats, rate),
    h("div", { class: "card" }, h("div", { class: "scroll" }, h("table", {}, head, body))));
};

// ---- Detections: live Sigma / YARA-L hits pushed over the WebSocket
views.detections = async (main) => {
  const [d, s] = await Promise.all([api("/api/v1/runtime/detections?limit=200").catch((e) => ({ detections: [], error: e.message })),
    api("/api/v1/runtime/sigma").catch(() => null)]);
  const body = h("tbody");
  const add = (x, live) => { body.prepend(h("tr", { class: live ? "new" : "" }, h("td", {}, fmt.t(x.timestamp)), h("td", {}, sev(x.level)), h("td", {}, x.title), h("td", { class: "mono" }, x.rule_id),
    h("td", {}, (x.techniques || []).join(", ")), h("td", { class: "mono" }, x.key || ""), h("td", {}, String(x.count ?? "")))); while (body.children.length > 500) body.lastChild.remove(); };
  (d.detections || []).slice().reverse().forEach((x) => add(x));
  const st = s?.stats || {};
  main.append(h("div", { class: "grid kpis" },
    h("div", { class: "card kpi" }, h("h2", {}, "Rules loaded"), h("div", { class: "v" }, fmt.n((s?.rules || []).length)), h("div", { class: "s" }, `${fmt.n((s?.errors || []).length)} rejected with a reason`)),
    h("div", { class: "card kpi" }, h("h2", {}, "Detections"), h("div", { class: "v" }, fmt.n(st.detections ?? (d.detections || []).length)), h("div", { class: "s" }, "since start")),
    h("div", { class: "card kpi" }, h("h2", {}, "Events evaluated"), h("div", { class: "v" }, fmt.n(st.events ?? st.evaluated)), h("div", { class: "s" }, "compiled IR in ulpf_core when built"))),
    d.error ? h("div", { class: "card" }, h("p", { class: "muted" }, d.error)) : null,
    card("Detections (live)", h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Level", "Rule", "Id", "ATT&CK", "Group", "Count"].map((c) => h("th", { scope: "col" }, c)))), body))),
    s ? card("Rules", table([["Rule", (r) => r.title], ["Level", (r) => sev(r.level)], ["ATT&CK", (r) => (r.techniques || []).join(", ")], ["Aggregation", (r) => r.aggregation ? "yes" : ""]], s.rules || [])) : null);
  state.unsub = subscribe((m) => { if (m.type === "detection") add(m.data, true); });
};

// ---- Evidence: seals, identity key, live verification
views.evidence = async (main) => {
  const [seals, pub] = await Promise.all([api("/api/v1/evidence/seals?limit=100").catch((e) => ({ error: e.message })), api("/api/v1/evidence/pubkey").catch(() => null)]);
  const out = h("div");
  const list = seals.seals || seals.items || (Array.isArray(seals) ? seals : []);
  main.append(card("Identity public key (give to verifiers out of band)", h("div", { class: "json" }, pub ? (pub.pem || pub.public_key || JSON.stringify(pub, null, 1)) : "evidence sealing not enabled")),
    h("div", { class: "card" }, h("h2", {}, "Verify the chain now"), h("div", { class: "row" },
      h("button", { class: "primary", onclick: async () => { out.replaceChildren(h("div", { class: "empty" }, "Recomputing Merkle roots from the raw journal…"));
        try { const r = await api("/api/v1/evidence/verify?check_store=true", { method: "POST" });
          out.replaceChildren(h("p", {}, h("span", { class: r.valid ? "status-pass" : "status-fail" }, r.valid ? "VERIFIED" : "FAILED"),
            ` — ${fmt.n(r.seals)} seals, ${fmt.n(r.records_checked)} records, ${fmt.n(r.signatures_checked)} signatures, ${fmt.n(r.events_checked)} stored events`),
            (r.problems || []).length ? h("div", { class: "json" }, r.problems.join("\n")) : null);
        } catch (e) { out.replaceChildren(h("div", { class: "empty" }, e.message)); } } }, "Verify seals, journal and store"),
      h("span", { class: "muted" }, "Offline / court use: ulpf forensic-kit DIR → ulpf-forensic-verify on an air-gapped workstation")), out),
    card("Seals (newest first)", seals.error ? h("div", { class: "empty" }, seals.error) : table([["Records", (s) => `${s.first_seq}…${s.last_seq}`], ["Count", (s) => fmt.n(s.count)],
      ["Merkle root", (s) => h("span", { class: "mono" }, String(s.merkle_root || "").slice(0, 24) + "…")], ["Signed", (s) => s.signature ? "Ed25519 (forward-secure)" : "HMAC v1"],
      ["Created", (s) => fmt.t(s.created_at)], ["Reason", (s) => s.reason || ""]], list.slice().reverse())));
};

// ---- Threat intel, risk and UEBA
views.intel = async (main) => {
  const [st, notables, anomalies, risk] = await Promise.all([api("/api/v1/intel/stats").catch(() => null), api("/api/v1/risk/notables?limit=50").catch(() => null),
    api("/api/v1/ueba/anomalies?limit=50").catch(() => null), api("/api/v1/risk/entities?limit=50").catch(() => null)]);
  const val = h("input", { placeholder: "IP, domain, URL, hash, e-mail…", "aria-label": "Indicator", style: { flex: "1" } }), res = h("div");
  const lookup = async () => { if (!val.value.trim()) return; try { const r = await api(`/api/v1/intel/lookup?value=${encodeURIComponent(val.value.trim())}`);
    res.replaceChildren(h("div", { class: "json" }, JSON.stringify(r, null, 2))); } catch (e) { res.replaceChildren(h("div", { class: "empty" }, e.message)); } };
  val.addEventListener("keydown", (e) => e.key === "Enter" && lookup());
  const rows = (x, k) => (x && (x[k] || x.items || x.entities || x.notables || x.anomalies)) || [];
  main.append(h("div", { class: "grid cols-even" },
    card("Threat intelligence", st ? h("div", { class: "json" }, JSON.stringify(st, null, 1).slice(0, 1500)) : h("div", { class: "empty" }, "intel not enabled"),
      h("div", { class: "row", style: { marginTop: "10px" } }, val, h("button", { class: "primary", onclick: lookup }, "Look up")), res),
    card("Risk notables", table([["Entity", (n) => `${n.entity_type || n.type || ""} ${n.value || n.entity || ""}`], ["Score", (n) => fmt.n(n.score ?? n.risk)], ["Why", (n) => (n.reasons || n.rules || []).slice?.(0, 3).join?.(", ") || ""]], rows(notables, "notables")))),
    h("div", { class: "grid cols-even" },
      card("Highest-risk entities", table([["Entity", (n) => `${n.entity_type || n.type || ""} ${n.value || n.entity || ""}`], ["Score", (n) => fmt.n(n.score ?? n.risk)], ["Threshold", (n) => fmt.n(n.threshold)]], rows(risk, "entities"))),
      card("UEBA anomalies", table([["Time", (a) => fmt.t(a.timestamp || a.time)], ["Kind", (a) => a.kind || a.type || ""], ["Actor", (a) => a.actor || a.user || a.identifier || ""], ["Detail", (a) => String(a.description || a.detail || "").slice(0, 120)]], rows(anomalies, "anomalies")))));
};

// ---- Cluster and runtime health
views.cluster = async (main) => {
  const [rs, cs] = await Promise.all([api("/api/v1/runtime/status").catch((e) => ({ error: e.message })), api("/api/v1/cluster/status").catch(() => null)]);
  if (rs.error) { main.append(card("Runtime", h("p", { class: "muted" }, `${rs.error} — start the live pipeline with \`ulpf run -c pipeline.yaml\` to see inputs, workers and outputs.`))); return; }
  const outputs = Object.entries(rs.outputs || {}).map(([k, v]) => ({ name: k, ...v }));
  const inputs = Object.entries(rs.inputs || {}).map(([k, v]) => ({ name: k, ...(typeof v === "object" ? v : { info: v }) }));
  main.append(h("div", { class: "grid kpis" },
    h("div", { class: "card kpi" }, h("h2", {}, "Mode"), h("div", { class: "v" }, rs.mode || "—"), h("div", { class: "s" }, `node ${rs.node} · up ${fmt.dur(rs.uptime_seconds)}`)),
    h("div", { class: "card kpi" }, h("h2", {}, "Journal"), h("div", { class: "v" }, fmt.n(rs.journal?.records_written)), h("div", { class: "s" }, `${rs.journal?.encrypted ? "AES-256-GCM" : "plain"} · sync ${rs.journal?.sync}`)),
    h("div", { class: "card kpi" }, h("h2", {}, "Workers"), h("div", { class: "v" }, fmt.n(rs.pipeline?.workers ?? rs.pipeline?.n)), h("div", { class: "s" }, rs.pipeline?.engine || "")),
    h("div", { class: "card kpi" }, h("h2", {}, "Egress"), h("div", { class: "v" }, rs.egress?.mode || "off"), h("div", { class: "s" }, `${Object.keys(rs.egress?.blocked || {}).length} destinations blocked`)),
    h("div", { class: "card kpi" }, h("h2", {}, "Memory limit"), h("div", { class: "v" }, rs.limits?.rss_mb ? `${fmt.n(rs.limits.rss_mb)} MB` : "—"), h("div", { class: "s" }, "limits.hard_memory_mb enforces it in the OS"))),
    h("div", { class: "grid cols-even" },
      card("Inputs", table([["Input", (i) => i.name], ["Type", (i) => i.type || i.kind || ""], ["Detail", (i) => JSON.stringify(i).slice(0, 140)]], inputs)),
      card("Outputs", table([["Output", (o) => o.name], ["Delivered", (o) => fmt.n(o.delivered ?? o.events_delivered)], ["Buffer", (o) => fmt.n(o.buffer?.events ?? o.pending)], ["Failures", (o) => fmt.n(o.failures ?? o.errors)]], outputs))),
    card("Cluster", cs ? h("div", { class: "json" }, JSON.stringify(cs, null, 1).slice(0, 6000)) : h("p", { class: "muted" }, "Single node (cluster.enabled: false). Set cluster.backend: raft with raft.peers for a consensus cluster.")));
};

// ---- Copilot
views.copilot = async (main) => {
  const status = await api("/api/v1/copilot/status").catch((e) => ({ backend: "unavailable", error: e.message }));
  const qn = h("input", { placeholder: "e.g. top 10 source ips with failed logins in the last 24 hours", "aria-label": "Question", style: { flex: "1" } });
  const lang = h("select", { "aria-label": "Language" }, ["kql", "spl", "hql"].map((d) => h("option", { value: d }, d === "spl" ? "SPL2" : d.toUpperCase())));
  const out = h("div"), tech = h("input", { placeholder: "T1110, T1059.001, T1486", "aria-label": "Techniques", style: { flex: "1" } }), tout = h("div");
  const ask = async () => { if (!qn.value.trim()) return; out.replaceChildren(h("div", { class: "empty" }, "Translating…"));
    try { const r = await api("/api/v1/copilot/nl2query", { method: "POST", body: { question: qn.value, language: lang.value } });
      const res = h("div");
      out.replaceChildren(h("p", {}, h("span", { class: r.valid ? "status-pass" : "status-fail" }, r.valid ? "VALID" : "NOT VALIDATED"), ` · ${r.origin} · ${r.elapsed_ms ?? "?"} ms — ${r.explanation}`),
        h("div", { class: "json" }, r.query), h("div", { class: "row", style: { marginTop: "8px" } },
          h("button", { class: "primary", disabled: !r.valid || !can("query:run"), onclick: async () => { res.replaceChildren(h("div", { class: "empty" }, "Running…"));
            try { const x = await api("/api/v1/query", { method: "POST", body: { dialect: r.language, query: r.query, start: r.start, max_rows: 500 } });
              const cols = (x.columns || []).map((c) => c.name || c); res.replaceChildren(table(cols.map((c) => [c, (row) => String(row[c] ?? "")]), x.rows || [])); }
            catch (e) { res.replaceChildren(h("div", { class: "empty" }, e.message)); } } }, "Run on the store"),
          h("button", { onclick: () => { const tabs = JSON.parse(store.get("ulpf.tabs", "null") || "null") || []; tabs.push({ name: `Copilot ${tabs.length + 1}`, dialect: r.language, text: r.query });
            store.set("ulpf.tabs", JSON.stringify(tabs), true); location.hash = "#/investigate"; } }, "Open in workbench")), res); }
    catch (e) { out.replaceChildren(h("div", { class: "empty" }, e.message)); } };
  qn.addEventListener("keydown", (e) => e.key === "Enter" && ask());
  main.append(card("Model", h("p", {}, h("strong", {}, status.backend), ` on ${status.device || "cpu"} · context ${fmt.n(status.n_ctx)} tokens · ${status.model || "no model file: deterministic rules engine"}`),
      h("p", { class: "muted" }, status.network || "offline"), (status.errors || []).length ? h("div", { class: "json" }, status.errors.join("\n")) : null),
    card("Ask in plain language → validated query", h("div", { class: "row" }, qn, lang, h("button", { class: "primary", disabled: !can("copilot:use"), onclick: ask }, "Translate")), out),
    card("Explain ATT&CK techniques and containment", h("div", { class: "row" }, tech, h("button", { disabled: !can("copilot:use"), onclick: async () => {
      try { const r = await api("/api/v1/copilot/explain", { method: "POST", body: { techniques: tech.value.split(/[ ,]+/).filter(Boolean) } });
        tout.replaceChildren(table([["Technique", (t) => t.technique], ["Name", (t) => t.name], ["Tactic", (t) => t.tactic], ["Containment", (t) => t.containment.map((c) => `${c.kind}: ${c.recommendation}`).join("; ")]], r.techniques)); }
      catch (e) { tout.replaceChildren(h("div", { class: "empty" }, e.message)); } } }, "Explain")), tout),
    h("p", { class: "muted" }, "Case triage narratives: open a case and press “Investigate with copilot”."));
};

// ---------------------------------------------------------------- shell
function applyTheme() { const t = store.get("ulpf.theme") || "system"; if (t === "system") document.documentElement.removeAttribute("data-theme"); else document.documentElement.dataset.theme = t; }
async function route() {
  const [path, query] = (location.hash.slice(2) || "cockpit").split("?"); const name = views[path] ? path : "cockpit";
  state.unsub?.(); state.unsub = null; state.cleanup?.(); state.cleanup = null;
  document.querySelectorAll(".nav nav a").forEach((a) => { if (a.dataset.route === name) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  $("#title").textContent = $(`.nav a[data-route="${name}"]`)?.textContent.replace(/^\W+/, "").trim() || name;
  const main = $("#main"); main.replaceChildren(); $(".nav").classList.remove("open");
  try { await views[name](main, new URLSearchParams(query || "")); }
  catch (e) { main.replaceChildren(h("div", { class: "card", role: "alert" }, h("h2", {}, "Unavailable"), h("p", {}, e.message),
    /401|403/.test(e.message) ? h("a", { href: "#/settings" }, "Set your API key") : null)); }
}
async function boot() {
  applyTheme();
  try { state.me = await api("/api/v1/console/me"); }
  catch (e) { state.me = null; $("#who").textContent = "not signed in"; if (!location.hash.includes("settings")) location.hash = "#/settings"; await route(); return; }
  if (!state.tenant) state.tenant = state.me.tenant;
  const ts = $("#tenant"); const list = state.me.tenants.includes("*") ? [...new Set([state.me.tenant, "default", state.tenant])] : state.me.tenants;
  ts.replaceChildren(...list.map((t) => h("option", { value: t, selected: t === state.tenant }, t)));
  ts.onchange = () => { state.tenant = ts.value; store.set("ulpf.tenant", ts.value, true); connect(); route(); };
  $("#who").replaceChildren(h("div", {}, h("strong", {}, state.me.name)), h("div", {}, `${state.me.role} · tenant ${state.tenant}`));
  connect(); await route();
}
$("#menu").addEventListener("click", () => $(".nav").classList.toggle("open"));
addEventListener("hashchange", route);
boot();
