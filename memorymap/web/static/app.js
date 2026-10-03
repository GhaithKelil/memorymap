"use strict";

/* ====================================================================================
   helpers
   ==================================================================================== */
const $ = (s, r = document) => r.querySelector(s);
const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const SEV_VAR = { CRITICAL: "--critical", HIGH: "--high", MEDIUM: "--medium", LOW: "--low", CLEAN: "--ok" };
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const IMG = (name) => `/static/img/${name}.png`;

const ICON = {
  search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
  refresh: '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>',
  copy: '<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  locate: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3m0 14v3M2 12h3m14 0h3"/><circle cx="12" cy="12" r="8"/>',
  cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v2m6-2v2M9 20v2m6-2v2M2 9h2m-2 6h2m16-6h2m-2 6h2"/>',
  overview: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
  findings: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><circle cx="11.5" cy="14.5" r="2.5"/><path d="M13.3 16.3 15 18"/>',
  anomalies: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  memory: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
  residue: '<circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><path d="M11 18H8a2 2 0 0 1-2-2V9"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  bolt: '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
  flame: '<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.4-.5-2-1-3-1.1-2.1-.2-4 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.2.4-2.4 1-3 0 1.4 1 2.5 2.5 2.5z"/>',
  layers: '<path d="m12 2 10 5-10 5L2 7l10-5z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/>',
};
const icon = (n) => {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("aria-hidden", "true");
  s.innerHTML = ICON[n]; // static, trusted path data only
  return s;
};

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "style") e.style.cssText = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return e;
}

const fmtBytes = (n) => {
  if (n >= 2 ** 30) return (n / 2 ** 30).toFixed(2) + " GB";
  if (n >= 2 ** 20) return (n / 2 ** 20).toFixed(1) + " MB";
  if (n >= 2 ** 10) return (n / 2 ** 10).toFixed(0) + " KB";
  return n + " B";
};
const hex = (n) => "0x" + n.toString(16).toUpperCase().padStart(12, "0");
const num = (n) => n.toLocaleString("en-US");
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
const sevBadge = (s) => el("span", { class: "sev " + s }, s);

async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || r.statusText);
  return body;
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("on");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("on"), 1600);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { toast("Copy failed"); }
}
const copyBtn = (text, label) => el("button", { class: "copy", title: label, "aria-label": label, onclick: (e) => { e.stopPropagation(); copyText(text); } }, icon("copy"));

/* cell meter: the same motif as the logo */
function meter(fraction, color, cells = 20, large = false) {
  const lit = Math.round(fraction * cells);
  return el("div", { class: "meter" + (large ? " lg" : ""), style: `--n:${cells};--c:${color}`, role: "img", "aria-label": `${Math.round(fraction * 100)} percent` },
    Array.from({ length: cells }, (_, i) => el("i", { class: i < lit ? "on" : "" })));
}

function emptyState(img, title, text) {
  return el("div", { class: "empty-state" }, el("img", { src: IMG(img), alt: "" }), el("strong", {}, title), el("span", {}, text));
}

/* sortable table headers */
function sortHead(label, key, sort, onSort, num = false) {
  const active = sort.key === key;
  return el("th", { class: num ? "num" : "", "aria-sort": active ? (sort.dir > 0 ? "ascending" : "descending") : "none" },
    el("button", { class: "sort", onclick: () => onSort(key) }, label, el("i", {}, active ? (sort.dir > 0 ? "↑" : "↓") : "")));
}
function nextSort(sort, key, defaultDir = 1) {
  return sort.key === key ? { key, dir: -sort.dir } : { key, dir: defaultDir };
}
function sortRows(rows, sort, getters) {
  const get = getters[sort.key];
  return rows.slice().sort((a, b) => {
    const x = get(a), y = get(b);
    return (typeof x === "string" ? x.localeCompare(y) : x - y) * sort.dir;
  });
}

/* ====================================================================================
   state
   ==================================================================================== */
const TABS = ["overview", "findings", "anomalies", "memory", "residue"];
const TAB_TITLE = { overview: "Overview", findings: "Findings", anomalies: "Anomalies", memory: "Memory map", residue: "Residue test" };
const state = {
  info: {}, result: null, snaps: [], activeId: null, tab: "overview", poll: null, procs: [],
  filters: { sev: "ALL", q: "", cat: "ALL", asev: "ALL" }, mapColor: "protect",
  residue: { before: null, after: null, status: "ALL" }, jumpToResidue: false,
  sort: { findings: { key: "severity", dir: 1 }, procs: { key: "rss", dir: -1 } },
  zoom: null, focusAddr: null, selected: null, mode: "picker",
};
const view = $("#view");

/* ====================================================================================
   theme, sidebar, page header
   ==================================================================================== */
const currentTheme = () => document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
function toggleTheme() {
  const t = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("mm-theme", t); } catch {}
  renderSide();
  if (state.tab === "memory" && state.result && $("#map")) drawMap();
}

const isMac = /Mac|iPhone|iPad/.test(navigator.platform);
const MOD = isMac ? "⌘" : "Ctrl";

function renderSide() {
  const r = state.result;
  const hot = r && r.counts.by_severity.CRITICAL > 0;
  const nav = r && el("nav", { class: "nav", "aria-label": "Sections" }, TABS.map((id) => {
    const count = { findings: r.counts.findings, anomalies: r.counts.anomalies, residue: state.snaps.length > 1 ? state.snaps.length : null }[id];
    return el("button", { "aria-current": state.tab === id ? "page" : null, onclick: () => setTab(id) },
      icon(id), TAB_TITLE[id], count != null && el("span", { class: "n" + (id === "anomalies" && hot ? " hot" : "") }, num(count)));
  }));
  const target = r && el("div", { class: "target", "data-tilt": "" },
    el("div", { class: "k" }, "Target"),
    el("div", { class: "name", title: r.process_name }, r.process_name),
    el("div", { class: "meta" }, `PID ${r.pid}`),
    state.snaps.length > 1 && el("select", { "aria-label": "Snapshot", onchange: (e) => loadResult(Number(e.target.value)) },
      state.snaps.map((s) => el("option", { value: s.id, selected: s.id === state.activeId }, "Snapshot " + s.label))),
    el("button", { class: "btn", onclick: rescan }, icon("refresh"), "Re-scan"));

  $("#side").replaceChildren(...[
    el("a", { class: "brand", href: "/", "aria-label": "MemoryMap" },
      el("img", { src: IMG("logo"), alt: "", width: 38, height: 38 }),
      el("div", {}, el("b", {}, "MemoryMap"), el("small", {}, "v" + document.body.dataset.version))),
    el("button", { class: "searchbtn", onclick: openPalette, "aria-label": "Open command palette" }, icon("search"), el("span", {}, "Search or jump to"), el("kbd", {}, MOD + " K")),
    nav,
    el("div", { class: "side-mid" },
      r && el("button", { class: "btn ghost", onclick: newTarget }, icon("plus"), "New target"),
      el("button", { class: "btn ghost", onclick: toggleTheme },
        icon(currentTheme() === "dark" ? "sun" : "moon"), currentTheme() === "dark" ? "Light theme" : "Dark theme")),
    el("div", { class: "side-foot" },
      state.info.admin != null && el("div", { class: "env" + (state.info.admin ? "" : " warn") }, state.info.admin ? "Elevated" : "Standard user"),
      target),
  ].filter(Boolean));
  bindTilt();
}

function renderHead(title, sub, actions = []) {
  $("#pagehead").replaceChildren(
    el("div", { class: "grow" }, el("h1", {}, title), sub && el("div", { class: "sub" }, sub)),
    el("div", { class: "acts" }, actions));
}

function resultActions() {
  const q = "?id=" + state.activeId;
  return [
    el("a", { class: "btn", href: "/export.html" + q, download: "" }, icon("download"), "Report"),
    el("a", { class: "btn", href: "/export.json" + q, download: "" }, icon("download"), "JSON"),
    el("button", { class: "btn primary", onclick: rescan, title: "Take another snapshot of the same process" }, icon("refresh"), "Re-scan"),
  ];
}

/* 3D tilt: elements marked data-tilt lean toward the pointer, with a moving glare */
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
function bindTilt(root = document) {
  if (reduceMotion) return;
  root.querySelectorAll("[data-tilt]:not([data-tilt-bound])").forEach((node) => {
    node.dataset.tiltBound = "1";
    node.addEventListener("pointermove", (e) => {
      const b = node.getBoundingClientRect();
      const x = (e.clientX - b.left) / b.width, y = (e.clientY - b.top) / b.height;
      node.style.setProperty("--ry", ((x - 0.5) * 9).toFixed(2) + "deg");
      node.style.setProperty("--rx", ((0.5 - y) * 7).toFixed(2) + "deg");
      node.style.setProperty("--mx", (x * 100).toFixed(1) + "%");
      node.style.setProperty("--my", (y * 100).toFixed(1) + "%");
      node.style.setProperty("--glare", "1");
    });
    node.addEventListener("pointerleave", () => {
      node.style.setProperty("--rx", "0deg"); node.style.setProperty("--ry", "0deg"); node.style.setProperty("--glare", "0");
    });
  });
}

async function newTarget() {
  closeDrawer();
  await api("/api/reset", { method: "POST" });
  state.snaps = [];
  showPicker();
}
function rescan() {
  if (!state.result) return;
  closeDrawer();
  state.jumpToResidue = true;
  startScan(state.result.pid);
}

/* ====================================================================================
   inspector drawer with live hex view
   ==================================================================================== */
let lastFocus = null;

function openDrawer({ kicker, sev, title, body, snapId, address, locate }) {
  const dr = $("#drawer");
  lastFocus = document.activeElement;
  const acts = el("div", { class: "drawer-acts" },
    address != null && el("button", { class: "btn sm", onclick: () => copyText(hex(address)) }, icon("copy"), "Copy address"),
    locate && el("button", { class: "btn sm", onclick: () => { closeDrawer(); locateOnMap(locate); } }, icon("locate"), "Show on map"));
  const close = el("button", { class: "drawer-x", "aria-label": "Close inspector", onclick: closeDrawer }, icon("x"));
  dr.replaceChildren(
    el("div", { class: "drawer-h" }, el("div", { class: "grow" },
      el("div", { class: "kicker" }, kicker, sev && sevBadge(sev)), el("h2", {}, title)), close),
    el("div", { class: "drawer-b" }, body, acts.children.length ? acts : null,
      address != null && el("section", {}, el("h4", {}, "Memory"), hexView(snapId, address))));
  dr.hidden = false;
  $("#scrim").hidden = false;
  requestAnimationFrame(() => { dr.classList.add("open"); $("#scrim").classList.add("on"); close.focus(); });
}

function closeDrawer() {
  const dr = $("#drawer");
  if (dr.hidden) return;
  dr.classList.remove("open");
  $("#scrim").classList.remove("on");
  state.selected = null;
  document.querySelectorAll("tr.row.sel").forEach((r) => r.classList.remove("sel"));
  setTimeout(() => { dr.hidden = true; $("#scrim").hidden = true; }, 180);
  if (lastFocus && document.body.contains(lastFocus)) lastFocus.focus();
}
$("#scrim").addEventListener("click", closeDrawer);

const kvList = (pairs) => el("dl", { class: "kv" }, pairs.filter(Boolean).map(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));

function hexView(snapId, address) {
  let length = 256;
  const body = el("div", { class: "hex-body" });
  const lenSeg = () => seg([[256, "256 B"], [512, "512 B"], [1024, "1 KB"]], length, (v) => { length = v; bar.replaceChild(lenSeg(), bar.querySelector(".seg")); load(); });
  const bar = el("div", { class: "hex-bar" }, lenSeg(), el("div", { class: "grow" }),
    el("button", { class: "btn sm", onclick: () => load() }, icon("refresh"), "Re-read"));
  const legend = el("div", { class: "hex-legend" });
  const note = el("div", { class: "hex-note" }, "Live read of the process right now; it may differ from the snapshot.");

  async function load() {
    body.replaceChildren(el("div", { class: "skeleton" }));
    legend.replaceChildren();
    try {
      const d = await api(`/api/peek?id=${snapId}&address=${address}&length=${length}`);
      body.replaceChildren(renderHex(d, address));
      const seen = new Map();
      d.marks.forEach((m) => seen.set(m.category + (m.redacted ? " (masked)" : ""), m.severity));
      legend.replaceChildren(...[...seen].map(([name, sev]) => el("span", { class: "sev " + sev }, name)));
      body.querySelector(".focus")?.scrollIntoView({ block: "center" });
    } catch (e) {
      body.replaceChildren(el("div", { class: "hex-err" }, e.message));
    }
  }
  load();
  return el("div", { class: "hex" }, bar, body, legend, note);
}

function renderHex(d, focus) {
  const marks = new Array(d.bytes.length).fill(null);
  d.marks.forEach((m) => { for (let i = m.start; i < m.end; i++) marks[i] = m; });
  const rows = [];
  for (let off = 0; off < d.bytes.length; off += 16) {
    const slice = d.bytes.slice(off, off + 16);
    const cls = (i) => { const m = marks[off + i]; return m ? "m " + m.severity : ""; };
    rows.push(el("div", { class: "hx-row" },
      el("span", { class: "hx-off" }, (d.start + off).toString(16).toUpperCase().padStart(10, "0")),
      el("span", { class: "hx-bytes" }, slice.map((b, i) => el("span", { class: cls(i) + (d.start + off + i === focus ? " focus" : ""), title: hex(d.start + off + i) },
        b == null ? "••" : b.toString(16).padStart(2, "0").toUpperCase()))),
      el("span", { class: "hx-ascii" }, slice.map((b, i) => el("span", { class: cls(i) }, b == null ? "•" : b >= 32 && b < 127 ? String.fromCharCode(b) : "·")))));
  }
  return el("div", {}, rows);
}

/* things that can be inspected */
function inspectFinding(f, snapId = state.activeId) {
  state.selected = f.address;
  openDrawer({
    kicker: "Finding", sev: f.severity, title: f.category, snapId, address: f.address, locate: f.address,
    body: kvList([
      ["Value", [el("span", { class: "mono" }, f.value), " ", copyBtn(f.value, "Copy value")]],
      ["Address", el("span", { class: "mono" }, hex(f.address))],
      ["Location", f.where || "unknown"],
      f.pattern && ["Pattern", el("span", { class: "mono" }, f.pattern)],
      ["Copies", `${num(f.count)} in memory`],
      f.encoding && ["Encoding", f.encoding],
      !state.result.revealed && ["Masking", el("span", { class: "dim" }, "Masked. Start the server with --reveal to see full values.")],
    ]),
  });
}

function inspectAnomaly(a) {
  openDrawer({
    kicker: "Anomaly", sev: a.severity, title: a.title, snapId: state.activeId, address: a.address, locate: a.address,
    body: [
      el("p", {}, a.description),
      kvList([
        ["Technique", el("span", { class: "tag" }, a.technique)],
        ["Region", el("span", { class: "mono" }, hex(a.address))],
        ["Size", fmtBytes(a.size)], ["Protection", el("span", { class: "mono" }, a.protect)], ["Type", a.region_kind],
        a.mapped_file && ["Backing file", a.mapped_file],
        a.detail && ["Evidence", a.detail],
      ]),
    ],
  });
}

function inspectRegion(g) {
  const r = state.result;
  const inside = r.findings.filter((f) => f.address >= g.b && f.address < g.b + g.s);
  const anoms = r.anomalies.filter((a) => a.address === g.b);
  const row = (sev, text, go) => el("button", { onclick: go }, sevBadge(sev), el("span", { class: "t" }, text));
  openDrawer({
    kicker: "Region", title: hex(g.b), snapId: state.activeId, address: g.b, locate: g.b,
    body: [
      kvList([["Size", fmtBytes(g.s)], ["Protection", el("span", { class: "mono" }, g.p)], ["Type", g.k], g.f && ["Backing file", g.f]]),
      (anoms.length || inside.length) ? el("section", {}, el("h4", {}, `Inside this region (${anoms.length + inside.length})`),
        el("div", { class: "chiplist" },
          anoms.map((a) => row(a.severity, a.title, () => inspectAnomaly(a))),
          inside.slice(0, 12).map((f) => row(f.severity, `${f.category} · ${f.value}`, () => inspectFinding(f))))) : null,
    ],
  });
}

/* ====================================================================================
   command palette
   ==================================================================================== */
const palette = { open: false, items: [], index: 0 };

function paletteCommands(query) {
  const q = query.trim().toLowerCase();
  const r = state.result;
  const cmds = [];
  if (r) {
    TABS.forEach((id) => cmds.push({ group: "Go to", label: TAB_TITLE[id], icon: id, run: () => setTab(id) }));
    cmds.push({ group: "Actions", label: "Re-scan this process", hint: "new snapshot", icon: "refresh", run: rescan });
    cmds.push({ group: "Actions", label: "Export HTML report", icon: "download", run: () => { location.href = `/export.html?id=${state.activeId}`; } });
    cmds.push({ group: "Actions", label: "Export JSON", icon: "download", run: () => { location.href = `/export.json?id=${state.activeId}`; } });
    cmds.push({ group: "Actions", label: "Scan a different process", icon: "plus", run: newTarget });
  }
  cmds.push({ group: "Actions", label: "Toggle light and dark theme", icon: currentTheme() === "dark" ? "sun" : "moon", run: toggleTheme });

  const score = (text) => { const t = text.toLowerCase(); return !q ? 0 : t.startsWith(q) ? 0 : t.includes(q) ? 1 : 9; };
  let out = cmds.filter((c) => score(c.label) < 9).sort((a, b) => score(a.label) - score(b.label));

  if (q.length >= 2 && r) {
    r.findings.filter((f) => `${f.category} ${f.value} ${f.where}`.toLowerCase().includes(q)).slice(0, 6)
      .forEach((f) => out.push({ group: "Findings", label: `${f.category} · ${f.value}`, hint: f.severity.toLowerCase(), icon: "findings", run: () => inspectFinding(f) }));
    r.anomalies.filter((a) => `${a.title} ${a.detail} ${a.technique}`.toLowerCase().includes(q)).slice(0, 4)
      .forEach((a) => out.push({ group: "Anomalies", label: a.title, hint: a.severity.toLowerCase(), icon: "anomalies", run: () => inspectAnomaly(a) }));
  }
  if (state.mode === "picker" && state.procs.length) {
    state.procs.filter((p) => !q || p.name.toLowerCase().includes(q) || String(p.pid) === q).slice(0, 8)
      .forEach((p) => out.push({ group: "Scan a process", label: p.name, hint: `PID ${p.pid} · ${p.rss_mb} MB`, icon: "cpu", run: () => startScan(p.pid) }));
  }
  return out;
}

function renderPalette() {
  const list = $("#palette-list");
  const items = palette.items;
  if (!items.length) { list.replaceChildren(el("li", { class: "palette-empty" }, "Nothing matches.")); return; }
  const nodes = [];
  let group = null;
  items.forEach((it, i) => {
    if (it.group !== group) { group = it.group; nodes.push(el("li", { class: "grp", role: "presentation" }, group)); }
    nodes.push(el("li", { class: "item", role: "option", id: "pi-" + i, "aria-selected": String(i === palette.index),
      onmousemove: () => { if (palette.index !== i) { palette.index = i; renderPalette(); } }, onclick: () => runPalette(i) },
      icon(it.icon), el("span", { class: "l" }, it.label), it.hint && el("span", { class: "h" }, it.hint)));
  });
  list.replaceChildren(...nodes);
  $(`#pi-${palette.index}`)?.scrollIntoView({ block: "nearest" });
}

function openPalette() {
  palette.open = true;
  $("#palette").hidden = false;
  const input = $("#palette-input");
  input.value = "";
  palette.items = paletteCommands("");
  palette.index = 0;
  renderPalette();
  input.focus();
}
function closePalette() {
  palette.open = false;
  $("#palette").hidden = true;
}
function runPalette(i) {
  const it = palette.items[i];
  if (!it) return;
  closePalette();
  it.run();
}
$("#palette-input").addEventListener("input", (e) => { palette.items = paletteCommands(e.target.value); palette.index = 0; renderPalette(); });
$("#palette").addEventListener("mousedown", (e) => { if (e.target.id === "palette") closePalette(); });
$("#palette-input").addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { e.preventDefault(); palette.index = Math.min(palette.items.length - 1, palette.index + 1); renderPalette(); }
  else if (e.key === "ArrowUp") { e.preventDefault(); palette.index = Math.max(0, palette.index - 1); renderPalette(); }
  else if (e.key === "Enter") { e.preventDefault(); runPalette(palette.index); }
});

document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); palette.open ? closePalette() : openPalette(); return; }
  if (e.key === "Escape") {
    if (palette.open) closePalette();
    else if (!$("#drawer").hidden) closeDrawer();
    return;
  }
  if (e.key === "/" && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName) && !palette.open) {
    const i = $("main input[type=search]");
    if (i) { e.preventDefault(); i.focus(); }
  }
});

/* ====================================================================================
   picker
   ==================================================================================== */
async function showPicker() {
  clearInterval(state.poll);
  state.result = null;
  state.mode = "picker";
  renderSide();
  renderHead("Choose a process", "Pick the process to inspect. Nothing leaves this machine.");
  const banner = $("#banner");
  banner.hidden = state.info.admin !== false;
  banner.textContent = "Not running elevated. Protected and other users’ processes can’t be opened; start the terminal as Administrator to include them.";

  const input = el("input", { type: "search", placeholder: "Filter by name, PID or user", autocomplete: "off", "aria-label": "Filter processes" });
  const tbody = el("tbody");
  const thead = el("thead");
  const count = el("span", { class: "dim" });
  const getters = { name: (p) => p.name.toLowerCase(), pid: (p) => p.pid, rss: (p) => p.rss_mb, user: (p) => p.username.toLowerCase() };

  const draw = () => {
    const sort = state.sort.procs;
    thead.replaceChildren(el("tr", {},
      sortHead("Process", "name", sort, onSort), sortHead("PID", "pid", sort, onSort),
      sortHead("Memory", "rss", sort, onSort, true), sortHead("User", "user", sort, onSort), el("th", {})));
    const q = input.value.trim().toLowerCase();
    const rows = sortRows(state.procs.filter((p) => !q || p.name.toLowerCase().includes(q) || String(p.pid) === q || p.username.toLowerCase().includes(q)), sort, getters);
    count.textContent = `${num(rows.length)} process${rows.length === 1 ? "" : "es"}`;
    tbody.replaceChildren(...(rows.length ? rows.slice(0, 200).map((p) =>
      el("tr", { class: "row", tabindex: 0, onclick: () => startScan(p.pid), onkeydown: (e) => { if (e.key === "Enter") startScan(p.pid); } },
        el("td", {}, p.name),
        el("td", { class: "mono dim" }, p.pid),
        el("td", { class: "num" }, p.rss_mb >= 1024 ? (p.rss_mb / 1024).toFixed(2) + " GB" : p.rss_mb.toFixed(1) + " MB"),
        el("td", { class: "dim" }, p.username || "—"),
        el("td", { class: "num" }, el("button", { class: "btn sm", onclick: (e) => { e.stopPropagation(); startScan(p.pid); } }, "Scan")))) :
      [el("tr", {}, el("td", { colspan: 5, class: "empty" }, "No process matches that filter."))]));
  };
  const onSort = (key) => { state.sort.procs = nextSort(state.sort.procs, key, key === "rss" ? -1 : 1); draw(); };
  input.addEventListener("input", draw);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") tbody.querySelector("tr.row")?.click(); });

  view.replaceChildren(
    el("section", { class: "panel hero", "data-tilt": "" },
      el("img", { class: "hero-art", src: IMG("hero"), alt: "" }),
      el("div", { class: "hero-copy" },
        el("h2", {}, "After the action, is the secret ", el("em", {}, "still in RAM?")),
        el("p", {}, "Scan a running process for credentials and injection-style anomalies, then take a second snapshot to see what survived."),
        el("div", { class: "pts" }, el("span", { class: "tag" }, "secret scanning"), el("span", { class: "tag" }, "residue test"), el("span", { class: "tag" }, "anomalies")))),
    el("div", { class: "toolbar" },
      el("div", { class: "search" }, icon("search"), input, el("kbd", {}, "/")),
      count, el("div", { class: "grow" }),
      el("button", { class: "btn", onclick: loadProcs }, icon("refresh"), "Refresh")),
    el("div", { class: "panel" }, el("div", { class: "table-wrap", style: "max-height:none" }, el("table", {}, thead, tbody))));
  bindTilt(view);

  async function loadProcs() {
    tbody.replaceChildren(el("tr", {}, el("td", { colspan: 5 }, el("div", { class: "skeleton" }))));
    state.procs = await api("/api/processes");
    draw();
  }
  await loadProcs();
  input.focus();
}

/* ====================================================================================
   scanning, with a live feed of discoveries
   ==================================================================================== */
async function startScan(pid) {
  try { await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ pid }) }); }
  catch (e) { toast(e.message); return; }
  watchScan();
}

function watchScan() {
  $("#banner").hidden = true;
  state.mode = "scan";
  const CELLS = 40;
  const phase = el("h2", {}, "Starting…");
  const sub = el("div", { class: "dim" });
  const bar = meter(0, css("--accent"), CELLS, true);
  const nF = el("b", {}, "0"), nA = el("b", {}, "0"), nB = el("b", {}, "0 MB");
  const feed = el("ul", { class: "feed", "aria-live": "polite" }, el("li", { class: "feed-empty", style: "display:block" }, "Findings appear here as they are discovered."));
  let lastSeq = 0;
  renderHead("Scanning", null);
  state.result = null;
  renderSide();
  view.replaceChildren(el("section", { class: "panel scanbox" }, phase, sub, bar,
    el("div", { class: "live" }, el("div", {}, nB, el("span", {}, "scanned")), el("div", {}, nF, el("span", {}, "findings")), el("div", {}, nA, el("span", {}, "anomalies"))),
    el("div", { class: "feedwrap" }, feed),
    el("button", { class: "btn danger", onclick: () => api("/api/cancel", { method: "POST" }) }, icon("stop"), "Cancel")));

  clearInterval(state.poll);
  const tick = async () => {
    const s = await api("/api/status");
    const p = s.progress;
    s.feed.filter((e) => e.seq > lastSeq).forEach((e) => {
      lastSeq = e.seq;
      feed.querySelector(".feed-empty")?.remove();
      feed.prepend(el("li", { class: "new" }, sevBadge(e.severity), el("span", {}, e.label), el("span", { class: "d" }, e.detail)));
      while (feed.children.length > 8) feed.lastChild.remove();
    });
    if (s.state === "scanning") {
      phase.textContent = cap(p.phase) + "…";
      sub.textContent = p.total_bytes ? `${Math.round(p.fraction * 100)}% of ${fmtBytes(p.total_bytes)}` : "Enumerating regions";
      const lit = Math.round(p.fraction * CELLS);
      [...bar.children].forEach((c, i) => c.classList.toggle("on", i < lit));
      nB.textContent = fmtBytes(p.done_bytes); nF.textContent = num(p.findings); nA.textContent = num(p.anomalies);
      return;
    }
    clearInterval(state.poll);
    if (s.state === "done") return loadResult();
    showMessage(s.state === "cancelled" ? "Scan cancelled" : "Scan failed", s.error || "The scan was stopped before it finished.");
  };
  state.poll = setInterval(() => tick().catch(() => {}), 350);
  tick();
}

function showMessage(title, text) {
  renderHead(title, null);
  view.replaceChildren(el("section", { class: "panel scanbox" }, el("h2", {}, title), el("p", { class: "dim" }, text),
    el("button", { class: "btn primary", onclick: showPicker }, "Choose another process")));
}

/* ====================================================================================
   results
   ==================================================================================== */
async function loadResult(id) {
  const status = await api("/api/status");
  state.snaps = status.snapshots;
  state.activeId = id ?? state.snaps[state.snaps.length - 1].id;
  state.result = await api("/api/result?id=" + state.activeId);
  state.mode = "result";
  state.filters = { sev: "ALL", q: "", cat: "ALL", asev: "ALL" };
  state.residue = { before: null, after: null, status: "ALL" };
  state.zoom = null;
  const [tabPart, ...extra] = location.hash.slice(1).split("&");
  state.tab = TABS.includes(tabPart) ? tabPart : "overview";
  if (state.jumpToResidue && state.snaps.length > 1) state.tab = "residue";
  state.jumpToResidue = false;
  history.replaceState(null, "", "#" + state.tab);
  $("#banner").hidden = true;
  renderResult();
  // Deep link: #findings&inspect=<address> opens the inspector on that finding.
  const target = extra.map((p) => p.split("=")).find(([k]) => k === "inspect");
  const finding = target && state.result.findings.find((f) => String(f.address) === target[1]);
  if (finding) inspectFinding(finding);
}

function setTab(id) {
  if (id !== "memory") state.focusAddr = null;
  state.tab = id;
  history.replaceState(null, "", "#" + id);
  renderResult();
}

function renderResult() {
  const r = state.result;
  const snap = state.snaps.find((s) => s.id === state.activeId);
  renderSide();
  renderHead(TAB_TITLE[state.tab], `${r.process_name} · PID ${r.pid}` + (snap ? ` · snapshot ${snap.label}` : ""), resultActions());
  view.replaceChildren();
  ({ overview: renderOverview, findings: renderFindings, anomalies: renderAnomalies, memory: renderMemory, residue: renderResidue })[state.tab](view);
  window.scrollTo(0, 0);
}

/* ---------- overview ---------- */
const SVGNS = "http://www.w3.org/2000/svg";
const svgEl = (tag, attrs = {}) => {
  const e = document.createElementNS(SVGNS, tag);
  Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
  return e;
};

/* smooth sparkline with a gradient fill; a single point draws a flat baseline */
let sparkId = 0;
function sparkline(values, color) {
  const W = 220, H = 56, id = "sp" + ++sparkId;
  const n = values.length;
  const max = Math.max(...values, 1), min = Math.min(...values, 0);
  const y = (v) => H - 10 - ((v - min) / (max - min || 1)) * (H - 26);
  const pts = n === 1 ? [[0, y(values[0])], [W, y(values[0])]] : values.map((v, i) => [(i * W) / (n - 1), y(v)]);
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 1; i < pts.length; i++) {
    const [x0, y0] = pts[i - 1], [x1, y1] = pts[i], mx = (x0 + x1) / 2;
    d += ` C${mx},${y0} ${mx},${y1} ${x1},${y1}`;
  }
  const s = svgEl("svg", { class: "spark", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", "aria-hidden": "true" });
  const defs = svgEl("defs");
  const g = svgEl("linearGradient", { id, x1: 0, y1: 0, x2: 0, y2: 1 });
  g.append(svgEl("stop", { offset: "0", "stop-color": color, "stop-opacity": ".38" }), svgEl("stop", { offset: "1", "stop-color": color, "stop-opacity": "0" }));
  defs.append(g);
  s.append(defs,
    svgEl("path", { d: `${d} L${W},${H} L0,${H} Z`, fill: `url(#${id})` }),
    svgEl("path", { d, fill: "none", stroke: color, "stroke-width": 2.5, "stroke-linecap": "round", "vector-effect": "non-scaling-stroke" }));
  return s;
}

/* concentric rings, one per severity, arc length = share of all items */
function donut(counts) {
  const total = SEVS.reduce((a, s) => a + counts[s], 0);
  const S = 210, C = S / 2, STROKE = 13;
  const svg = svgEl("svg", { viewBox: `0 0 ${S} ${S}`, width: S, height: S, role: "img", "aria-label": `${total} items by severity` });
  const rings = [];
  SEVS.forEach((sev, i) => {
    const r = 92 - i * 20, circ = 2 * Math.PI * r;
    const color = css(SEV_VAR[sev]);
    svg.append(svgEl("circle", { class: "track", cx: C, cy: C, r, "stroke-width": STROKE }));
    const ring = svgEl("circle", { class: "ring", cx: C, cy: C, r, "stroke-width": STROKE, stroke: color, "stroke-dasharray": circ, "stroke-dashoffset": circ, style: `filter:drop-shadow(0 0 6px ${color})` });
    svg.append(ring);
    rings.push([ring, circ, total ? counts[sev] / total : 0]);
  });
  requestAnimationFrame(() => rings.forEach(([ring, circ, frac]) => ring.setAttribute("stroke-dashoffset", frac ? circ * (1 - Math.max(frac, 0.04)) : circ)));
  return el("div", { class: "donut" }, svg, el("div", { class: "mid" }, el("b", {}, num(total)), el("span", {}, "items")));
}

const BAR_GRADIENTS = [["#5b7cff", "#8f5bff"], ["#ff4d6a", "#ff8a5c"], ["#2ee6b6", "#4db7ff"], ["#ffd25a", "#ff9a4d"], ["#9b5bff", "#ff5bd1"], ["#4db7ff", "#5b7cff"], ["#ff8a5c", "#ffd25a"]];
function vbars(entries) {
  if (!entries.length) return el("div", { class: "empty" }, "Nothing to chart.");
  const max = Math.max(1, ...entries.map((e) => e[1]));
  return el("div", { class: "vbars" }, entries.map(([name, v], i) => {
    const [g1, g2] = BAR_GRADIENTS[i % BAR_GRADIENTS.length];
    return el("div", { class: "vbar", title: `${name}: ${v}` },
      el("span", { class: "v" }, num(v)),
      el("div", { class: "bar", style: `height:${Math.max(6, (v / max) * 78)}%;--g1:${g1};--g2:${g2};animation-delay:${i * 60}ms` }),
      el("span", { class: "l" }, name));
  }));
}

function hbars(entries, fmt = num) {
  const max = Math.max(1, ...entries.map((e) => e[1]));
  if (!entries.length) return el("div", { class: "dim" }, "Nothing to show.");
  return el("div", { class: "hbars" }, entries.map(([name, v, color]) =>
    el("div", { class: "hbar" },
      el("span", { class: "name", title: name }, name),
      el("span", { class: "track" }, el("i", { style: `width:${Math.max(3, (v / max) * 100)}%;${color ? `--hb:${color};--hb-glow:${color}` : ""}` })),
      el("span", { class: "v" }, fmt(v)))));
}

/* one stat card: icon chip, delta against the previous snapshot, big number, sparkline */
function statCard({ label, value, icon: ic, grad, glow, color, series }) {
  const prev = series.length > 1 ? series[series.length - 2] : null;
  const cur = series[series.length - 1];
  const diff = prev == null ? null : cur - prev;
  const delta = el("span", { class: "delta " + (diff == null || diff === 0 ? "flat" : diff > 0 ? "up" : "down") },
    diff == null ? "baseline" : diff === 0 ? "no change" : (diff > 0 ? "+" : "−") + Math.abs(diff));
  return el("div", { class: "stat", "data-tilt": "" },
    el("div", { class: "top" }, el("span", { class: "chip-ic", style: `--cg:${grad};--cglow:${glow}` }, icon(ic)), delta),
    el("div", { class: "label" }, label),
    el("div", { class: "big", style: `color:${color}` }, value),
    sparkline(series, color));
}

function overviewStats(r) {
  const sev = r.counts.by_severity;
  const hist = state.snaps.length ? state.snaps : [{ score: r.score, by_severity: sev }];
  const series = (fn) => hist.map(fn);
  const riskColor = `var(${SEV_VAR[r.label]})`;
  const prevScore = hist.length > 1 ? hist[hist.length - 2].score : null;
  const scoreDiff = prevScore == null ? null : r.score - prevScore;

  const risk = el("div", { class: "stat hero-stat", "data-tilt": "" },
    el("div", { class: "top" }, el("span", { class: "chip-ic" }, icon("shield")),
      el("span", { class: "delta" }, scoreDiff == null ? "baseline" : scoreDiff === 0 ? "no change" : (scoreDiff > 0 ? "+" : "−") + Math.abs(scoreDiff))),
    el("div", { class: "label" }, "Risk score"),
    el("div", { class: "big" }, r.score, el("small", {}, "/ 100")),
    el("div", { class: "sevword", style: "margin-top:4px" }, r.label),
    meter(r.score / 100, "#fff"));

  return el("div", { class: "grid stats" }, risk,
    statCard({ label: "Critical", value: sev.CRITICAL, icon: "bolt", grad: "linear-gradient(135deg,#ff4d6a,#ff7a5c)", glow: "rgba(255,77,106,.8)", color: css("--critical"), series: series((s) => s.by_severity.CRITICAL) }),
    statCard({ label: "High", value: sev.HIGH, icon: "flame", grad: "linear-gradient(135deg,#ff9a4d,#ffbf4d)", glow: "rgba(255,154,77,.8)", color: css("--high"), series: series((s) => s.by_severity.HIGH) }),
    statCard({ label: "Medium and low", value: sev.MEDIUM + sev.LOW, icon: "layers", grad: "linear-gradient(135deg,#6f86ff,#9b5bff)", glow: "rgba(123,100,255,.8)", color: css("--low"), series: series((s) => s.by_severity.MEDIUM + s.by_severity.LOW) }));
}

function renderOverview(root) {
  const r = state.result;
  const sev = r.counts.by_severity;
  const total = r.counts.findings + r.counts.anomalies;

  const cats = {};
  r.findings.forEach((f) => { cats[f.category] = (cats[f.category] || 0) + 1; });
  const catEntries = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 7);
  const kinds = {};
  r.anomalies.forEach((a) => { kinds[a.title] = (kinds[a.title] || 0) + 1; });
  const kindEntries = Object.entries(kinds).sort((a, b) => b[1] - a[1]);
  const pc = { RWX: css("--c-rwx"), Executable: css("--c-exec"), Writable: css("--c-write"), "Read-only": css("--c-read") };
  const protEntries = ["RWX", "Executable", "Writable", "Read-only"].map((k) => [k, r.stats.by_protect[k] || 0, pc[k]]).filter((e) => e[1]);

  const top = [
    ...r.anomalies.map((a) => ({ sev: a.severity, title: a.title, sub: hex(a.address), go: () => inspectAnomaly(a) })),
    ...r.findings.map((f) => ({ sev: f.severity, title: f.category + " · " + f.value, sub: hex(f.address), go: () => inspectFinding(f) })),
  ].sort((a, b) => SEV_RANK[a.sev] - SEV_RANK[b.sev]).slice(0, 7);

  const panel = (title, meta, body) => el("section", { class: "panel" }, el("div", { class: "panel-h" }, el("h3", {}, title), meta && el("span", { class: "dim" }, meta)), body);

  const legend = el("div", { class: "donut-legend" }, SEVS.map((s) =>
    el("div", { style: `--c:var(${SEV_VAR[s]})` }, el("i"), cap(s.toLowerCase()), el("b", {}, sev[s]))));

  root.append(overviewStats(r),
    el("div", { class: "grid three" },
      panel("Severity", `${num(total)} items`, el("div", { class: "donut-wrap" }, total ? [donut(sev), legend] : el("div", { class: "dim" }, "No items."))),
      panel("Finding categories", `${num(r.counts.findings)} findings`, el("div", { class: "panel-b" }, vbars(catEntries)))),
    el("div", { class: "grid main" },
      panel("Priority items", "worst first", top.length ?
        el("ul", { class: "plist" }, top.map((t) => el("li", { tabindex: 0, onclick: t.go, onkeydown: (e) => { if (e.key === "Enter") t.go(); } },
          sevBadge(t.sev), el("span", { class: "t" }, t.title), el("span", { class: "s" }, t.sub)))) :
        emptyState("empty-clean", "Nothing to report", "No sensitive data or injection-style behaviour was found in the scanned memory.")),
      el("div", { class: "stack-col" },
        panel("Anomaly types", `${num(r.counts.anomalies)} detected`, el("div", { class: "panel-b" }, hbars(kindEntries))),
        panel("Committed memory", fmtBytes(r.committed_bytes), el("div", { class: "panel-b" }, hbars(protEntries, fmtBytes))))));
  bindTilt(root);
}

/* ---------- findings ---------- */
function seg(options, current, onPick) {
  return el("div", { class: "seg", role: "group" }, options.map(([v, label]) =>
    el("button", { "aria-pressed": String(current === v), onclick: () => onPick(v) }, label)));
}
const SEV_OPTIONS = () => [["ALL", "All"], ...SEVS.map((s) => [s, cap(s.toLowerCase())])];

function renderFindings(root) {
  const r = state.result, f = state.filters;
  const cats = [...new Set(r.findings.map((x) => x.category))].sort();
  const body = el("tbody");
  const thead = el("thead");
  const more = el("div", { class: "empty", hidden: true });
  const input = el("input", { type: "search", value: f.q, placeholder: "Search values and categories", autocomplete: "off", "aria-label": "Search findings" });
  let limit = 300;
  const getters = {
    severity: (x) => SEV_RANK[x.severity], category: (x) => x.category, value: (x) => x.value,
    where: (x) => x.where || "", address: (x) => x.address, count: (x) => x.count,
  };
  const onSort = (key) => { state.sort.findings = nextSort(state.sort.findings, key); draw(); };

  const draw = () => {
    const sort = state.sort.findings;
    thead.replaceChildren(el("tr", {},
      sortHead("Severity", "severity", sort, onSort), sortHead("Category", "category", sort, onSort), sortHead("Value", "value", sort, onSort),
      sortHead("Location", "where", sort, onSort), sortHead("Address", "address", sort, onSort), sortHead("Count", "count", sort, onSort, true)));
    const q = f.q.toLowerCase();
    const rows = sortRows(r.findings.filter((x) => (f.sev === "ALL" || x.severity === f.sev) && (f.cat === "ALL" || x.category === f.cat) &&
      (!q || x.value.toLowerCase().includes(q) || x.category.toLowerCase().includes(q))), sort, getters);
    body.replaceChildren();
    if (!rows.length) {
      body.append(el("tr", {}, el("td", { colspan: 6 }, r.findings.length ?
        el("div", { class: "empty" }, "No findings match these filters.") :
        emptyState("empty-clean", "No findings", "Nothing sensitive was found in the scanned memory."))));
    }
    rows.slice(0, limit).forEach((x) => {
      const open = () => { document.querySelectorAll("tr.row.sel").forEach((t) => t.classList.remove("sel")); tr.classList.add("sel"); inspectFinding(x); };
      const tr = el("tr", { class: "row" + (state.selected === x.address ? " sel" : ""), tabindex: 0, onclick: open, onkeydown: (e) => { if (e.key === "Enter") open(); } },
        el("td", {}, sevBadge(x.severity)), el("td", {}, x.category),
        el("td", { class: "mono value-cell", title: x.value }, x.value),
        el("td", { class: "dim" }, x.where),
        el("td", { class: "mono dim" }, hex(x.address)), el("td", { class: "num mono" }, num(x.count)));
      body.append(tr);
    });
    more.hidden = rows.length <= limit;
    more.replaceChildren(el("button", { class: "btn", onclick: () => { limit += 300; draw(); } }, `Show more (${num(rows.length - limit)} remaining)`));
  };

  input.addEventListener("input", () => { f.q = input.value; limit = 300; draw(); });
  const sevSeg = () => seg(SEV_OPTIONS(), f.sev, (v) => { f.sev = v; limit = 300; bar.replaceChild(sevSeg(), bar.querySelector(".seg")); draw(); });
  const catSel = el("select", { "aria-label": "Category", onchange: (e) => { f.cat = e.target.value; limit = 300; draw(); } },
    el("option", { value: "ALL" }, "All categories"), cats.map((c) => el("option", { value: c, selected: f.cat === c }, c)));
  const bar = el("div", { class: "toolbar" }, el("div", { class: "search" }, icon("search"), input, el("kbd", {}, "/")), sevSeg(), catSel);

  root.append(bar, el("div", { class: "panel" }, el("div", { class: "table-wrap" }, el("table", {}, thead, body)), more),
    el("p", { class: "hint" }, "Select a row to inspect the memory around it."));
  draw();
}

/* ---------- anomalies ---------- */
function renderAnomalies(root) {
  const r = state.result, f = state.filters;
  const list = el("div", { class: "panel" });
  const draw = () => {
    const rows = r.anomalies.filter((a) => f.asev === "ALL" || a.severity === f.asev);
    list.replaceChildren(...(rows.length ? rows.map((a) =>
      el("article", { class: "anom " + a.severity },
        el("div", { class: "row" }, sevBadge(a.severity), el("span", { class: "tag" }, a.technique)),
        el("h4", {}, a.title), el("p", {}, a.description),
        el("div", { class: "row mono dim" },
          el("span", {}, hex(a.address)), el("span", {}, fmtBytes(a.size)), el("span", {}, a.protect), el("span", {}, a.region_kind), a.mapped_file && el("span", {}, a.mapped_file)),
        a.detail && el("div", { class: "evidence" }, a.detail),
        el("div", { class: "drawer-acts", style: "margin-top:10px" },
          el("button", { class: "btn sm", onclick: () => inspectAnomaly(a) }, "Inspect memory"),
          el("button", { class: "btn sm", onclick: () => locateOnMap(a.address) }, icon("locate"), "Show on map")))) :
      [r.anomalies.length ? el("div", { class: "empty" }, "No anomalies match this severity.") :
        emptyState("empty-clean", "No anomalies detected", "No injection-style behaviour was seen in this process.")]));
  };
  const sevSeg = () => seg(SEV_OPTIONS(), f.asev, (v) => { f.asev = v; bar.replaceChild(sevSeg(), bar.querySelector(".seg")); draw(); });
  const bar = el("div", { class: "toolbar" }, sevSeg());
  root.append(bar, list);
  draw();
}

/* ---------- residue test ---------- */
const VERDICT_SEV = { RESIDUE: "CRITICAL", MINOR: "MEDIUM", CLEAN: "CLEAN", INCONCLUSIVE: "LOW" };
const VERDICT_TITLE = { RESIDUE: "Secrets survived", MINOR: "Minor residue", CLEAN: "Clean", INCONCLUSIVE: "Inconclusive" };

function renderResidue(root) {
  const snaps = state.snaps;
  if (snaps.length < 2) {
    const sensitive = state.result.findings.filter((f) => f.sensitive).length;
    const step = (n, title, text) => el("li", {}, el("b", {}, n), el("div", {}, el("strong", {}, title), el("p", { class: "dim" }, text)));
    root.append(el("section", { class: "panel guide" },
      el("div", {},
        el("h2", {}, "Does this process wipe its secrets?"),
        el("p", { class: "dim", style: "margin:0;max-width:56ch" }, "Take a snapshot while a secret is in use, do something that should clear it, then take another. MemoryMap shows what is still sitting in RAM."),
        el("ol", { class: "steps" },
          step("1", "Baseline taken", sensitive ? `This scan holds ${sensitive} sensitive finding${sensitive === 1 ? "" : "s"}. Make sure the secret you care about is in use right now.` : "This scan holds no sensitive findings, so there is nothing to wipe yet. Use the app so it loads the secret, then start over."),
          step("2", "Do the action", "Sign out, lock the vault, close the document, end the session."),
          step("3", "Re-scan", "Findings are matched by fingerprint: still present, wiped or new.")),
        el("button", { class: "btn primary", onclick: rescan }, icon("refresh"), "Re-scan and compare")),
      el("img", { src: IMG("empty-diff"), alt: "A grid of memory cells before and after: some cleared, a few remaining" })));
    return;
  }

  const rs = state.residue;
  rs.before ??= snaps[0].id;  // the baseline
  rs.after ??= snaps[snaps.length - 1].id;
  const pick = (key) => el("select", { "aria-label": key, onchange: (e) => { rs[key] = Number(e.target.value); load(); } },
    snaps.map((s) => el("option", { value: s.id, selected: s.id === rs[key] }, s.label)));
  const host = el("div");
  const lifetime = el("div");
  root.append(el("div", { class: "toolbar" },
    el("label", { class: "dim" }, "Before ", pick("before")), el("label", { class: "dim" }, "After ", pick("after")),
    el("div", { class: "grow" }),
    el("button", { class: "btn", onclick: rescan }, icon("refresh"), "Take another snapshot")), host, lifetime);

  async function load() {
    host.replaceChildren(el("div", { class: "skeleton" }));
    try { draw(await api(`/api/diff?before=${rs.before}&after=${rs.after}`)); }
    catch (e) { host.replaceChildren(el("div", { class: "panel empty" }, e.message)); }
  }

  function draw(d) {
    const sev = VERDICT_SEV[d.verdict];
    const count = (label, n, color) => el("div", {}, el("b", { style: `color:var(${color})` }, n), el("span", {}, label));
    const body = el("tbody");
    const paint = () => {
      const rows = d.items.filter((i) => rs.status === "ALL" || i.status === rs.status);
      body.replaceChildren(...(rows.length ? rows.map((i) => {
        const here = i.after || i.before;
        const snapId = i.after ? rs.after : rs.before;
        const copies = i.status === "persisted" ? `${i.before.count} → ${i.after.count}` : String(here.count);
        const open = () => inspectFinding({ category: i.category, severity: i.severity, value: i.value, address: here.address, count: here.count, where: here.where }, snapId);
        return el("tr", { class: "row", tabindex: 0, onclick: open, onkeydown: (e) => { if (e.key === "Enter") open(); } },
          el("td", {}, el("span", { class: "state " + i.status }, { persisted: "Still present", wiped: "Wiped", new: "New" }[i.status])),
          el("td", {}, sevBadge(i.severity)), el("td", {}, i.category),
          el("td", { class: "mono value-cell", title: i.value }, i.value),
          el("td", { class: "dim" }, here.where || "—"), el("td", { class: "mono dim" }, hex(here.address)), el("td", { class: "num mono" }, copies));
      }) : [el("tr", {}, el("td", { colspan: 7, class: "empty" }, "Nothing in this group."))]));
    };
    const filter = () => seg([["ALL", "All"], ["persisted", "Still present"], ["wiped", "Wiped"], ["new", "New"]], rs.status,
      (v) => { rs.status = v; chips.replaceChild(filter(), chips.firstChild); paint(); });
    const chips = el("div", { class: "toolbar" }, filter());
    paint();
    host.replaceChildren(
      el("section", { class: "panel verdict " + sev },
        el("div", {}, el("div", { class: "sev " + sev }, VERDICT_TITLE[d.verdict]), el("p", {}, d.verdict_text),
          !d.same_process && el("p", { class: "dim" }, "These snapshots are from different processes.")),
        el("div", { class: "counts" }, count("still present", d.counts.persisted, "--critical"), count("wiped", d.counts.wiped, "--ok"), count("new", d.counts.new, "--medium"))),
      chips,
      el("div", { class: "panel" }, el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, ["Status", "Severity", "Category", "Value", "Location", "Address", "Copies"].map((h, i) => el("th", { class: i === 6 ? "num" : "" }, h)))), body))),
      el("p", { class: "hint" }, "Select a row to inspect the memory. Compared by keyed fingerprint; URLs, host:port, API paths and low-severity module data are ignored."));
  }

  async function drawLifetime() {
    try {
      const t = await api("/api/timeline");
      lifetime.replaceChildren(lifetimePanel(t));
    } catch { /* the diff above already explains what is missing */ }
  }
  load();
  drawLifetime();
}

/* the secret lifetime matrix: one row per secret, one column per snapshot */
function lifetimePanel(t) {
  const n = t.snapshots.length;
  const rows = t.rows.slice(0, 40);
  const grid = el("div", { class: "mx", style: `grid-template-columns: minmax(300px, 380px) repeat(${n}, 44px)` });
  grid.append(el("div", { class: "corner" }, "Secret"));
  t.snapshots.forEach((s) => grid.append(el("div", { class: "col", title: s.label }, "#" + s.id)));

  const stillThere = rows.filter((r) => r.cells[n - 1]).length;
  rows.forEach((row) => {
    const first = row.cells.findIndex(Boolean);
    const last = row.cells.length - 1 - [...row.cells].reverse().findIndex(Boolean);
    const cellsOf = [];
    const lab = el("div", { class: "lab", title: `${row.category} · ${row.value}` }, sevBadge(row.severity), el("span", { class: "t" }, row.category), el("span", { class: "v" }, row.value.slice(0, 22)));
    const parts = [lab];
    row.cells.forEach((c, i) => {
      const snap = t.snapshots[i];
      let node;
      if (c) {
        node = el("button", { class: "cell on", style: `--c:var(${SEV_VAR[row.severity]})`, title: `${snap.label}: ${c.count} cop${c.count === 1 ? "y" : "ies"}, ${c.where}`,
          "aria-label": `${row.category} present in snapshot ${snap.id}`,
          onclick: () => inspectFinding({ category: row.category, severity: row.severity, value: row.value, address: c.address, count: c.count, where: c.where }, snap.id) });
      } else if (i > last) {
        node = el("span", { class: "cell wiped", title: `${snap.label}: wiped` });
      } else {
        node = el("span", { class: "cell pre", title: i < first ? `${snap.label}: not yet present` : `${snap.label}: absent` });
      }
      parts.push(el("div", { class: "cellbox" }, node));
    });
    const wrap = [...parts];
    wrap.forEach((p) => {
      p.addEventListener("mouseenter", () => wrap.forEach((q) => q.classList.add("hl")));
      p.addEventListener("mouseleave", () => wrap.forEach((q) => q.classList.remove("hl")));
    });
    grid.append(...parts);
  });

  const legend = el("div", { class: "mx-legend" },
    el("span", {}, el("span", { class: "cell on", style: "--c:var(--high)" }), "present"),
    el("span", {}, el("span", { class: "cell wiped" }), "wiped"),
    el("span", {}, el("span", { class: "cell pre" }), "not yet seen"),
    el("span", { class: "dim" }, "Click a filled cell to inspect that moment in memory."));
  return el("section", { class: "panel", style: "margin-top:16px" },
    el("div", { class: "panel-h" }, el("h3", {}, "Secret lifetime"), el("span", { class: "dim" }, `${rows.length} tracked · ${stillThere} in the latest snapshot`)),
    rows.length ? el("div", { class: "matrix" }, grid) : el("div", { class: "empty" }, "No sensitive findings to track."),
    rows.length ? legend : null);
}

/* ---------- memory map ---------- */
const KIND_VAR = { Private: "--c-write", Mapped: "--c-exec", Image: "--c-read", Unknown: "--low" };
let mapGeom = [];

function regionColor(g) {
  if (state.mapColor === "kind") return css(KIND_VAR[g.k] || "--low");
  if (g.x && g.w) return css("--c-rwx");
  if (g.x) return css("--c-exec");
  if (g.w) return css("--c-write");
  return css("--c-read");
}

const visibleRegions = () => state.zoom ? state.result.regions.slice(state.zoom.from, state.zoom.to + 1) : state.result.regions;

function drawMap() {
  const cv = $("#map");
  if (!cv) return;
  const dpr = devicePixelRatio || 1;
  const W = cv.clientWidth, H = cv.clientHeight;
  cv.width = W * dpr; cv.height = H * dpr;
  const ctx = cv.getContext("2d");
  ctx.scale(dpr, dpr);
  const regs = visibleRegions();
  const offset = state.zoom ? state.zoom.from : 0;
  const weight = (s) => Math.log2(s / 4096 + 1) + 0.6;
  const total = regs.reduce((a, g) => a + weight(g.s), 0);
  const gap = regs.length > 400 ? 0 : 1;
  const usable = W - gap * regs.length;
  let x = 0;
  mapGeom = [];
  const red = css("--critical");
  regs.forEach((g, i) => {
    const w = Math.max(1, (weight(g.s) / total) * usable);
    const color = regionColor(g);
    const grad = ctx.createLinearGradient(0, 22, 0, H);
    grad.addColorStop(0, color);
    grad.addColorStop(1, color.length === 7 ? color + "55" : color);
    ctx.fillStyle = grad;
    if (w > 5 && ctx.roundRect) { ctx.beginPath(); ctx.roundRect(x, 22, w, H - 22, [4, 4, 0, 0]); ctx.fill(); }
    else ctx.fillRect(x, 22, w, H - 22);
    if (g.a.length) {
      ctx.save();
      ctx.shadowColor = red; ctx.shadowBlur = 12; ctx.fillStyle = red;
      ctx.beginPath(); ctx.arc(x + Math.max(w, 3) / 2, 8, 4, 0, Math.PI * 2); ctx.fill();
      ctx.restore();
    }
    mapGeom.push({ x, w, g, gi: offset + i });
    x += w + gap;
  });
  const focus = state.focusAddr != null && mapGeom.find((m) => state.focusAddr >= m.g.b && state.focusAddr < m.g.b + m.g.s);
  if (focus) {
    ctx.strokeStyle = css("--text");
    ctx.lineWidth = 2;
    ctx.strokeRect(focus.x - 1.5, 20.5, Math.max(focus.w, 2) + 3, H - 20);
    ctx.fillStyle = css("--text");
    const cx = focus.x + Math.max(focus.w, 2) / 2;
    ctx.beginPath(); ctx.moveTo(cx - 5, 0); ctx.lineTo(cx + 5, 0); ctx.lineTo(cx, 9); ctx.fill();
  }
}

function locateOnMap(address) {
  const regs = state.result.regions;
  const gi = regs.findIndex((g) => address >= g.b && address < g.b + g.s);
  if (gi < 0) { toast("That region isn't in the map view"); return; }
  if (state.zoom && (gi < state.zoom.from || gi > state.zoom.to)) state.zoom = null;
  state.focusAddr = address;
  setTab("memory");
}

function renderMemory(root) {
  const r = state.result;
  const cv = el("canvas", { id: "map", role: "img", "aria-label": "Address-ordered map of committed memory regions. Click a region to inspect it, drag to zoom." });
  const tip = el("div", { class: "tip", hidden: true });
  const sel = el("div", { class: "selrect", hidden: true });
  const wrap = el("div", { class: "mapwrap" }, cv, sel, tip);
  const tbody = el("tbody");
  const flags = { exec: false, flagged: false };
  const zoomBox = el("div");

  const geomAt = (x) => {
    let lo = 0, hi = mapGeom.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1, m = mapGeom[mid];
      if (x < m.x) hi = mid - 1; else if (x > m.x + Math.max(m.w, 2)) lo = mid + 1; else return m;
    }
    return null;
  };

  const refresh = () => { drawMap(); drawTable(); drawZoom(); };

  let dragFrom = null;
  cv.addEventListener("mousedown", (e) => { dragFrom = e.offsetX; sel.hidden = true; });
  cv.addEventListener("mousemove", (e) => {
    if (dragFrom != null && Math.abs(e.offsetX - dragFrom) > 4) {
      sel.hidden = false; tip.hidden = true;
      sel.style.left = Math.min(dragFrom, e.offsetX) + "px"; sel.style.width = Math.abs(e.offsetX - dragFrom) + "px";
      return;
    }
    const hit = geomAt(e.offsetX);
    if (!hit) { tip.hidden = true; return; }
    const g = hit.g;
    tip.replaceChildren(
      el("div", { class: "mono" }, hex(g.b)), el("div", {}, `${fmtBytes(g.s)} · ${g.p} · ${g.k}`),
      g.f && el("div", { class: "dim" }, g.f), g.a.length && el("div", { style: "color:var(--critical)" }, g.a.join(", ")),
      el("div", { class: "faint" }, "click to inspect · drag to zoom"));
    tip.hidden = false;
    tip.style.left = Math.min(e.offsetX + 14, wrap.clientWidth - tip.offsetWidth - 4) + "px";
    tip.style.top = "140px";
  });
  cv.addEventListener("mouseleave", () => { tip.hidden = true; });
  const onUp = (e) => {
    if (dragFrom == null) return;
    const from = dragFrom; dragFrom = null; sel.hidden = true;
    const rect = cv.getBoundingClientRect();
    const x1 = Math.min(Math.max(e.clientX - rect.left, 0), rect.width);
    if (Math.abs(x1 - from) > 6) {
      const lo = Math.min(from, x1), hi = Math.max(from, x1);
      const picked = mapGeom.filter((m) => m.x + m.w >= lo && m.x <= hi);
      if (picked.length > 1) { state.zoom = { from: picked[0].gi, to: picked[picked.length - 1].gi }; refresh(); }
    } else {
      const hit = geomAt(from);
      if (hit) inspectRegion(hit.g);
    }
  };
  if (state.mapUp) removeEventListener("mouseup", state.mapUp);
  state.mapUp = onUp;
  addEventListener("mouseup", onUp);

  function drawZoom() {
    zoomBox.replaceChildren(state.zoom ? el("div", { class: "zoompill" },
      `Zoomed to ${num(state.zoom.to - state.zoom.from + 1)} regions`,
      el("button", { class: "btn sm", onclick: () => { state.zoom = null; refresh(); } }, "Reset zoom")) : el("span", { class: "faint" }, "Drag across the map to zoom"));
  }

  const keyItems = () => state.mapColor === "kind"
    ? [["Private", "--c-write"], ["Mapped", "--c-exec"], ["Image", "--c-read"]]
    : [["Read + write + execute", "--c-rwx"], ["Executable", "--c-exec"], ["Writable", "--c-write"], ["Read-only", "--c-read"]];
  const keys = el("div", { class: "keys" },
    ...keyItems().map(([n, v]) => el("span", { style: `--dot:var(${v})` }, n)),
    el("span", { style: "--dot:var(--critical)" }, "Flagged (marker above)"));

  function drawTable() {
    let rows = visibleRegions().slice();
    if (flags.exec) rows = rows.filter((g) => g.x);
    if (flags.flagged) rows = rows.filter((g) => g.a.length);
    rows.sort((a, b) => b.s - a.s);
    tbody.replaceChildren(...(rows.length ? rows.slice(0, 200).map((g) => el("tr", { class: "row" + (state.focusAddr != null && state.focusAddr >= g.b && state.focusAddr < g.b + g.s ? " sel" : ""), tabindex: 0,
      onclick: () => inspectRegion(g), onkeydown: (e) => { if (e.key === "Enter") inspectRegion(g); } },
      el("td", { class: "mono" }, hex(g.b)), el("td", { class: "num mono" }, fmtBytes(g.s)), el("td", { class: "mono" }, g.p), el("td", {}, g.k),
      el("td", { class: "dim" }, g.f || "—"), el("td", {}, g.a.length ? el("span", { style: "color:var(--critical)" }, g.a.join(", ")) : ""))) :
      [el("tr", {}, el("td", { colspan: 6, class: "empty" }, "No regions match."))]));
  }
  const check = (key, label) => el("label", {}, el("input", { type: "checkbox", onchange: (e) => { flags[key] = e.target.checked; drawTable(); } }), label);

  root.append(
    el("section", { class: "panel mb" },
      el("div", { class: "panel-h" }, el("h3", {}, "Committed regions by address"),
        seg([["protect", "Protection"], ["kind", "Type"]], state.mapColor, (v) => { state.mapColor = v; renderResult(); })),
      el("div", { class: "panel-b" }, wrap, keys, el("div", { style: "margin-top:12px" }, zoomBox),
        r.regions_truncated > 0 && el("p", { class: "faint", style: "margin:12px 0 0" }, `Showing the ${num(r.regions.length)} largest of ${num(r.region_count)} regions.`))),
    el("section", { class: "panel" },
      el("div", { class: "panel-h" }, el("h3", {}, "Regions, largest first"), el("div", { class: "checks" }, check("exec", "Executable only"), check("flagged", "Flagged only"))),
      el("div", { class: "table-wrap" }, el("table", {}, el("thead", {}, el("tr", {}, ["Base", "Size", "Protect", "Type", "Backing file", "Flags"].map((h, i) => el("th", { class: i === 1 ? "num" : "" }, h)))), tbody))));
  requestAnimationFrame(refresh);
}

new ResizeObserver(() => { if (state.tab === "memory" && state.result && $("#map")) drawMap(); }).observe(document.body);

addEventListener("hashchange", () => {
  const id = location.hash.slice(1).split("&")[0];
  if (state.result && id !== state.tab && TABS.includes(id)) setTab(id);
});

/* ====================================================================================
   boot
   ==================================================================================== */
(async function boot() {
  renderSide();
  try {
    state.info = await api("/api/info");
    renderSide();
    const s = await api("/api/status");
    if (s.state === "scanning") return watchScan();
    if (s.state === "done") return loadResult();
    return showPicker();
  } catch (e) {
    showMessage("Can’t reach the server", e.message);
  }
})();
