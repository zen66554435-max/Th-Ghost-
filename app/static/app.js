/* TH Ghost — لوحة التحكم. كل الإدراجات عبر textContent حصراً لمنع XSS مخزن. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const CHECK_LABELS = {
  server: "الخادم والإعدادات", injection: "الحقن", access: "التحكم بالوصول",
  auth: "المصادقة والجلسات", api: "أمان API", files: "أمان الملفات",
  client: "جانب العميل", business: "منطق الأعمال",
};
const STATUS_AR = { queued: "في الطابور", running: "يعمل", completed: "مكتمل",
                    stopped: "متوقف", failed: "فشل" };
const SEV_COLORS = { "حرج": "#ff5470", "عالٍ": "#ff9f43", "متوسط": "#feca57",
                     "منخفض": "#54a0ff", "معلوماتية": "#93a1b5" };

let state = { projects: [], scans: [], currentScan: null, findings: [], routes: [] };
let pollTimer = null;

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 3500);
}

async function api(path, opts = {}) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = `خطأ ${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch (e) { /* ignore */ }
    throw new Error(msg);
  }
  return r.json();
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}

/* ---------- التنقل ---------- */
$$(".tab").forEach((b) => b.addEventListener("click", () => {
  $$(".tab").forEach((x) => x.classList.remove("active"));
  $$(".view").forEach((x) => x.classList.remove("active"));
  b.classList.add("active");
  $("#view-" + b.dataset.view).classList.add("active");
  if (b.dataset.view === "auditlog") loadAuditLog();
  if (b.dataset.view === "scans") loadScans();
}));

/* ---------- لوحة المعلومات ---------- */
async function loadStats() {
  const s = await api("/api/stats");
  const cards = $("#stats-cards");
  cards.textContent = "";
  [["المواقع", s.projects], ["الفحوصات", s.scans], ["النتائج الكلي", s.findings]].forEach(([lbl, n]) => {
    const c = el("div", null, "card");
    c.append(el("div", n, "num"), el("div", lbl, "lbl"));
    cards.append(c);
  });
  const confirmed = (s.by_confidence || {})["مؤكدة"] || 0;
  const c = el("div", null, "card");
  c.append(el("div", confirmed, "num"), el("div", "نتائج مؤكدة", "lbl"));
  cards.append(c);
  drawBars("#sev-bars", s.by_severity || {}, SEV_COLORS);
  drawBars("#conf-bars", s.by_confidence || {}, {});
}

function drawBars(sel, data, colors) {
  const host = $(sel);
  host.textContent = "";
  const max = Math.max(1, ...Object.values(data));
  if (!Object.keys(data).length) { host.append(el("p", "لا بيانات بعد.", "muted")); return; }
  for (const [k, v] of Object.entries(data)) {
    const row = el("div", null, "bar-row");
    row.append(el("span", k, "bar-lbl"));
    const track = el("div", null, "bar-track");
    const fill = el("div", null, "bar-fill");
    fill.style.width = Math.round((v / max) * 100) + "%";
    fill.style.background = colors[k] || "var(--accent)";
    track.append(fill);
    row.append(track, el("span", v));
    host.append(row);
  }
}

/* ---------- المواقع ---------- */
async function loadProjects() {
  state.projects = (await api("/api/projects")).projects;
  const tb = $("#projects-table tbody");
  tb.textContent = "";
  for (const p of state.projects) {
    const tr = el("tr");
    tr.append(el("td", p.name));
    tr.append(el("td", p.origin));
    tr.append(el("td", (p.scope_prefixes || []).join(", ")));
    tr.append(el("td", p.accounts_count));
    const ls = p.last_scan;
    tr.append(el("td", ls ? `${STATUS_AR[ls.status] || ls.status} — ${ls.summary.findings_total ?? 0} نتيجة` : "—"));
    const act = el("td");
    const bScan = el("button", "فحص", "btn small primary");
    bScan.addEventListener("click", () => openScanDialog(p));
    const bAcc = el("button", "الحسابات", "btn small");
    bAcc.addEventListener("click", () => openAccountsDialog(p));
    const bDeps = el("button", "تدقيق تبعيات", "btn small");
    bDeps.addEventListener("click", () => openDepsDialog(p));
    const bDel = el("button", "حذف", "btn small danger");
    bDel.addEventListener("click", async () => {
      if (!confirm(`حذف المشروع «${p.name}» وكل فحوصاته؟`)) return;
      await api(`/api/projects/${p.id}`, { method: "DELETE" });
      toast("حُذف المشروع.");
      loadProjects(); loadStats();
    });
    act.append(bScan, " ", bAcc, " ", bDeps, " ", bDel);
    tr.append(act);
    tb.append(tr);
  }
}

$("#btn-add-project").addEventListener("click", () => $("#dlg-project").showModal());
$("#form-project").addEventListener("submit", async (ev) => {
  if (ev.submitter && ev.submitter.value === "cancel") return;
  ev.preventDefault();
  const fd = new FormData(ev.target);
  try {
    await api("/projects", { method: "POST", body: new URLSearchParams(fd) });
    $("#dlg-project").close();
    ev.target.reset();
    toast("أُضيف الموقع وتحقق حارس النطاق منه.");
    loadProjects(); loadStats();
  } catch (e) { toast(e.message); }
});

/* ---------- الفحص ---------- */
let scanProjectId = null;
function openScanDialog(p) {
  scanProjectId = p.id;
  const host = $("#checks-list");
  host.textContent = "";
  for (const [k, lbl] of Object.entries(CHECK_LABELS)) {
    const lab = el("label");
    const cb = el("input");
    cb.type = "checkbox"; cb.name = "check"; cb.value = k; cb.checked = true;
    lab.append(cb, document.createTextNode(lbl));
    host.append(lab);
  }
  $("#dlg-scan").showModal();
}
$("#form-scan").addEventListener("submit", async (ev) => {
  if (ev.submitter && ev.submitter.value === "cancel") return;
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const checks = $$('#checks-list input:checked').map((c) => c.value);
  if (!checks.length) { toast("اختر نوع فحص واحداً على الأقل."); return; }
  const body = {
    depth: fd.get("depth"),
    rate_rps: parseFloat(fd.get("rate_rps")),
    max_duration_sec: parseInt(fd.get("max_duration_sec"), 10),
    checks,
    use_accounts: fd.get("use_accounts") === "on",
  };
  try {
    const r = await api(`/api/projects/${scanProjectId}/scans`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    $("#dlg-scan").close();
    toast(`أُدرج الفحص #${r.scan_id} في الطابور (الموضع ${r.queue_position}).`);
    $$(".tab").find((t) => t.dataset.view === "scans").click();
  } catch (e) { toast(e.message); }
});

/* ---------- الحسابات ---------- */
let accProjectId = null;
async function openAccountsDialog(p) {
  accProjectId = p.id;
  await renderAccounts();
  $("#dlg-accounts").showModal();
}
async function renderAccounts() {
  const list = $("#accounts-list");
  list.textContent = "";
  const { accounts } = await api(`/api/projects/${accProjectId}/accounts`);
  if (!accounts.length) list.append(el("li", "لا حسابات بعد."));
  for (const a of accounts) {
    const li = el("li");
    li.append(el("span", `${a.label} — ${a.username}`));
    const b = el("button", "حذف", "btn small danger");
    b.addEventListener("click", async () => {
      await api(`/api/projects/${accProjectId}/accounts/${a.id}`, { method: "DELETE" });
      renderAccounts();
    });
    li.append(b);
    list.append(li);
  }
}
$("#form-account").addEventListener("submit", async (ev) => {
  if (ev.submitter && ev.submitter.value === "close") return;
  ev.preventDefault();
  const fd = new FormData(ev.target);
  try {
    await api(`/api/projects/${accProjectId}/accounts`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label: fd.get("label"), username: fd.get("username"), password: fd.get("password") }),
    });
    ev.target.reset();
    toast("أُضيف الحساب (لن تُعرض كلمة المرور مجدداً).");
    renderAccounts();
  } catch (e) { toast(e.message); }
});

/* ---------- تدقيق التبعيات ---------- */
let depsProjectId = null;
function openDepsDialog(p) { depsProjectId = p.id; $("#dlg-deps").showModal(); }
$("#form-deps").addEventListener("submit", async (ev) => {
  if (ev.submitter && ev.submitter.value === "cancel") return;
  ev.preventDefault();
  const files = $("#deps-files").files;
  if (!files.length) { toast("اختر ملفاً واحداً على الأقل."); return; }
  const fd = new FormData();
  for (const f of files) fd.append("files", f);
  try {
    const r = await api(`/api/projects/${depsProjectId}/deps-audit`, { method: "POST", body: fd });
    $("#dlg-deps").close();
    toast(`اكتمل التدقيق: ${r.findings} نتيجة من ${r.dependencies} تبعية.`);
    loadScans(); loadStats();
  } catch (e) { toast(e.message); }
});

/* ---------- الفحوصات ---------- */
async function loadScans() {
  state.scans = (await api("/api/scans")).scans;
  const tb = $("#scans-table tbody");
  tb.textContent = "";
  for (const s of state.scans) {
    const tr = el("tr");
    tr.append(el("td", s.id));
    tr.append(el("td", s.project_name || s.project_id));
    const st = el("td"); st.append(el("span", STATUS_AR[s.status] || s.status, `status ${s.status}`)); tr.append(st);
    const tdP = el("td");
    if (s.status === "running" || s.status === "queued") {
      const pr = el("progress"); pr.max = 100; pr.value = Math.min(100, s.progress || 0);
      tdP.append(pr, document.createTextNode(` ${s.progress || 0} مساراً`));
    } else tdP.append(el("span", "—"));
    tr.append(tdP);
    tr.append(el("td", (s.summary && s.summary.findings_total) ?? "—"));
    tr.append(el("td", s.started_at || "—"));
    const act = el("td");
    const bView = el("button", "التفاصيل", "btn small");
    bView.addEventListener("click", () => loadScanDetail(s.id));
    act.append(bView);
    if (s.status === "running" || s.status === "queued") {
      const bStop = el("button", "إيقاف", "btn small danger");
      bStop.addEventListener("click", async () => {
        await api(`/api/scans/${s.id}/stop`, { method: "POST" });
        toast("طُلب إيقاف الفحص.");
        loadScans();
      });
      act.append(" ", bStop);
    }
    const bRescan = el("button", "إعادة الفحص", "btn small");
    bRescan.addEventListener("click", async () => {
      try {
        const r = await api(`/api/projects/${s.project_id}/scans`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(s.config || {}),
        });
        toast(`أُعيد الفحص كـ #${r.scan_id}.`);
        loadScans();
      } catch (e) { toast(e.message); }
    });
    act.append(" ", bRescan);
    tr.append(act);
    tb.append(tr);
  }
  const anyActive = state.scans.some((s) => s.status === "running" || s.status === "queued");
  clearTimeout(pollTimer);
  if (anyActive) pollTimer = setTimeout(loadScans, 1500);
  if (state.currentScan) {
    const cur = state.scans.find((s) => s.id === state.currentScan);
    if (cur && (cur.status === "running" || cur.status === "queued")) {
      pollTimer = setTimeout(() => loadScanDetail(cur.id, true), 1500);
    }
  }
}

async function loadScanDetail(sid, silent = false) {
  const d = await api(`/api/scans/${sid}`);
  state.currentScan = sid;
  state.findings = d.findings || [];
  state.routes = d.routes || [];
  $("#scan-detail-panel").classList.remove("hidden");
  $("#scan-detail-title").textContent = `تفاصيل الفحص #${sid} — ${d.project_name || ""}`;
  const s = d.summary || {};
  const grid = $("#scan-summary");
  grid.textContent = "";
  [["الحالة", STATUS_AR[d.status] || d.status], ["النمط", s.mode || "—"],
   ["المسارات", s.routes ?? "—"], ["الطلبات", s.requests ?? "—"],
   ["المدة (ث)", s.duration_sec ?? "—"], ["النتائج", s.findings_total ?? state.findings.length],
  ].forEach(([k, v]) => {
    const cell = el("div", null, "cell");
    cell.append(el("b", k), document.createTextNode(String(v)));
    grid.append(cell);
  });
  if (s.notes && s.notes.length) {
    const cell = el("div", null, "cell");
    cell.append(el("b", "ملاحظات المحركات"), document.createTextNode(s.notes.join(" | ")));
    grid.append(cell);
  }
  fillFilters();
  renderFindings();
  renderRoutes();
  $("#btn-report-md").onclick = () => { location.href = `/api/scans/${sid}/report`; };
  $("#btn-report-json").onclick = () => { location.href = `/api/scans/${sid}/export.json`; };
  if (!silent) $("#scan-detail-panel").scrollIntoView({ behavior: "smooth" });
}

function fillFilters() {
  const uniq = (arr) => [...new Set(arr)];
  const fill = (sel, values, keepFirst) => {
    const s = $(sel);
    const cur = s.value;
    s.textContent = "";
    s.append(el("option", keepFirst, ""));
    s.querySelector("option").value = "";
    for (const v of values) { const o = el("option", v, ""); o.value = v; s.append(o); }
    s.value = cur;
  };
  fill("#filter-severity", uniq(state.findings.map((f) => f.severity)), "كل الشدائد");
  fill("#filter-confidence", uniq(state.findings.map((f) => f.confidence)), "كل مستويات الثقة");
  fill("#filter-category", uniq(state.findings.map((f) => f.category)), "كل الفئات");
}
["#filter-severity", "#filter-confidence", "#filter-category", "#filter-search"].forEach((sel) =>
  $(sel).addEventListener("input", renderFindings));

function renderFindings() {
  const sev = $("#filter-severity").value, conf = $("#filter-confidence").value,
        cat = $("#filter-category").value, q = $("#filter-search").value.trim();
  const tb = $("#findings-table tbody");
  tb.textContent = "";
  const rows = state.findings.filter((f) =>
    (!sev || f.severity === sev) && (!conf || f.confidence === conf) &&
    (!cat || f.category === cat) && (!q || (f.title + f.url).includes(q)));
  if (!rows.length) { const tr = el("tr"); const td = el("td", "لا نتائج مطابقة."); td.colSpan = 6; tr.append(td); tb.append(tr); return; }
  for (const f of rows) {
    const tr = el("tr");
    const tdS = el("td"); tdS.append(el("span", f.severity, `badge ${f.severity}`)); tr.append(tdS);
    tr.append(el("td", f.title));
    tr.append(el("td", f.category));
    tr.append(el("td", f.confidence));
    const tdU = el("td"); tdU.append(el("code", `${f.method} ${f.url}`)); tr.append(tdU);
    const tdB = el("td");
    const b = el("button", "التفاصيل", "btn small");
    b.addEventListener("click", () => showFinding(f));
    tdB.append(b);
    tr.append(tdB);
    tb.append(tr);
  }
}

function showFinding(f) {
  const host = $("#finding-detail");
  host.textContent = "";
  host.append(el("h3", f.title));
  const dl = el("dl");
  const pairs = [
    ["الفئة", f.category], ["الشدة", f.severity], ["الثقة", f.confidence],
    ["CVSS", f.cvss ?? "—"], ["العنوان URL", `${f.method} ${f.url}`],
    ["المعامل", f.parameter || "—"], ["الموقع", f.location || "—"],
    ["الدليل", f.evidence], ["السبب", f.cause], ["الأثر", f.impact],
    ["الإصلاح", f.recommendation], ["المرجع", f.reference || "—"],
    ["إعادة الاختبار", f.retest || "—"], ["المحرك", f.engine || "—"],
  ];
  for (const [k, v] of pairs) { dl.append(el("dt", k), el("dd", v)); }
  host.append(dl);
  $("#dlg-finding").showModal();
}
$("#btn-close-finding").addEventListener("click", () => $("#dlg-finding").close());

function renderRoutes() {
  const tb = $("#routes-table tbody");
  tb.textContent = "";
  for (const r of state.routes.slice(0, 300)) {
    const tr = el("tr");
    const tdU = el("td"); tdU.append(el("code", r.url)); tr.append(tdU);
    tr.append(el("td", r.source));
    tr.append(el("td", r.status_code ?? "—"));
    tr.append(el("td", (r.params || []).join(", ")));
    tr.append(el("td", r.discovered_at || "—"));
    tb.append(tr);
  }
}

/* ---------- سجل التدقيق ---------- */
async function loadAuditLog() {
  const { entries } = await api("/api/audit-log");
  const tb = $("#audit-table tbody");
  tb.textContent = "";
  for (const e of entries) {
    const tr = el("tr");
    tr.append(el("td", e.ts), el("td", e.action), el("td", e.detail));
    tb.append(tr);
  }
}

/* ---------- إقلاع ---------- */
loadStats(); loadProjects(); loadScans();
setInterval(loadStats, 15000);
