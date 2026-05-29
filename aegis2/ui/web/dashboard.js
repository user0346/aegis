/* ============================================================
   AEGIS V2 — Dashboard + Event-Stream Renderer (v2.0.8)
   ------------------------------------------------------------
   Befüllt, was bisher leer blieb:
     - Stat-Kacheln (#stat-events/threats/pending/domains) + Footer
       (#footer-modules/#footer-uptime)  -> via cmd "stats" (Polling,
       da der Service KEINE stats pusht, nur Events broadcastet).
     - Live Debug Stream (#debug-log)    -> via eventReceived (Push).
     - Recent Threats (#threats-list)    -> THREAT/CRITICAL-Events.
     - Event Stream Tab (#events-list)   -> alle Events, mit Filtern.

   Self-contained: haengt eigene Listener an window.aegis (Qt erlaubt
   mehrere Slots pro Signal) — kein Eingriff in app.js noetig.
   ============================================================ */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const SEV_RANK = { INFO: 1, WARN: 2, THREAT: 3, CRITICAL: 4 };
  const MAX_STREAM = 500;
  const MAX_EVENTS = 300;

  let paused = false;
  let frameCount = 0;
  let rateBase = Date.now();
  let connectedAt = null;
  const knownSources = new Set();
  const events = [];   // jüngste zuerst (für Event-Stream-Tab)

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));
  }

  // ---------- Stat-Kacheln + Footer ----------
  function renderStats(d) {
    if (!d) return;
    const set = (id, v) => { const e = $(id); if (e) e.textContent = (v == null ? "—" : v); };
    set("stat-events", d.events_24h);
    set("stat-threats", d.threats_24h);
    set("stat-pending", d.quarantine_pending);
    set("stat-domains", d.domains_blocked);
    const fm = $("footer-modules");
    if (fm && d.modules_total != null) {
      let _t = `Modules: ${d.modules_running || 0}/${d.modules_total || 0}`;
      if (d.baseline_known != null) _t += ` · Baseline: ${d.baseline_known} gelernt`;
      fm.textContent = _t;
    }
  }

  // ---------- Uptime (clientseitig ab connect) ----------
  function tickUptime() {
    const fu = $("footer-uptime");
    if (!fu) return;
    if (!connectedAt) { fu.textContent = "Uptime: —"; return; }
    let s = Math.floor((Date.now() - connectedAt) / 1000);
    const h = Math.floor(s / 3600); s -= h * 3600;
    const m = Math.floor(s / 60); const ss = s - m * 60;
    fu.textContent = "Uptime: " + (h > 0 ? h + "h " : "") + m + "m " + ss + "s";
  }

  // ---------- Live Debug Stream ----------
  function addSource(src) {
    if (!src || knownSources.has(src)) return;
    knownSources.add(src);
    const sel = $("debug-source");
    if (!sel) return;
    const o = document.createElement("option");
    o.value = src; o.textContent = src;
    sel.appendChild(o);
  }
  function streamPasses(ev) {
    const minSev = ($("debug-sev") || {}).value || "";
    if (minSev && (SEV_RANK[ev.severity] || 0) < (SEV_RANK[minSev] || 0)) return false;
    const src = ($("debug-source") || {}).value || "";
    if (src && ev.source !== src) return false;
    const q = (($("debug-search") || {}).value || "").toLowerCase();
    if (q && !((ev.message || "") + " " + (ev.source || "") + " " + (ev.category || "")).toLowerCase().includes(q)) return false;
    return true;
  }
  function fmtLine(ev) {
    const t = new Date((ev.ts ? ev.ts * 1000 : Date.now())).toLocaleTimeString();
    const sev = (ev.severity || "INFO");
    return "[" + t + "] " + (sev + "        ").slice(0, 8) + " " +
           (ev.source || "?") + ": " + (ev.message || "") + "\n";
  }
  function appendStream(ev) {
    frameCount++;
    addSource(ev.source);
    const log = $("debug-log");
    if (!log || paused || !streamPasses(ev)) return;
    log.appendChild(document.createTextNode(fmtLine(ev)));
    while (log.childNodes.length > MAX_STREAM) log.removeChild(log.firstChild);
    log.scrollTop = log.scrollHeight;
  }
  function rerenderStream() {
    const log = $("debug-log");
    if (!log) return;
    const out = [];
    for (let i = events.length - 1; i >= 0; i--) {
      if (streamPasses(events[i])) out.push(fmtLine(events[i]));
    }
    log.textContent = out.slice(-MAX_STREAM).join("");
    log.scrollTop = log.scrollHeight;
  }

  // ---------- Recent Threats (Dashboard) ----------
  function addThreat(ev) {
    if (ev.severity !== "THREAT" && ev.severity !== "CRITICAL") return;
    const ol = $("threats-list");
    if (!ol) return;
    const empty = ol.querySelector(".empty");
    if (empty) empty.remove();
    const li = document.createElement("li");
    li.className = ev.severity === "CRITICAL" ? "row-bad" : "row-warn";
    li.textContent = "[" + ev.severity + "] " + (ev.source || "?") + ": " + (ev.message || "");
    ol.insertBefore(li, ol.firstChild);
    while (ol.children.length > 30) ol.removeChild(ol.lastChild);
  }

  // ---------- Event Stream (Threats-Tab) ----------
  function renderEventList() {
    const ol = $("events-list");
    if (!ol) return;
    const fs = ($("filter-severity") || {}).value || "";
    const fc = ($("filter-category") || {}).value || "";
    const fq = (($("filter-search") || {}).value || "").toLowerCase();
    const rows = events.filter((ev) => {
      if (fs && ev.severity !== fs) return false;
      if (fc && ev.category !== fc) return false;
      if (fq && !((ev.message || "") + " " + (ev.source || "")).toLowerCase().includes(fq)) return false;
      return true;
    }).slice(0, 200);
    ol.innerHTML = rows.map((ev) => {
      const cls = (ev.severity === "CRITICAL" || ev.severity === "THREAT") ? "row-bad"
                : (ev.severity === "WARN" ? "row-warn" : "");
      return '<li class="' + cls + '"><span class="ev-sev mono">' + esc(ev.severity) +
             '</span> <span class="ev-src mono">' + esc(ev.source) + '</span> ' + esc(ev.message) + '</li>';
    }).join("");
  }
  function addEvent(ev) {
    events.unshift(ev);
    if (events.length > MAX_EVENTS) events.pop();
    renderEventList();
  }

  // ---------- Event-Eingang (von eventReceived) ----------
  function onEvent(ev) {
    if (!ev) return;
    if (ev.t === "cmd_result") {
      if (ev.ok && ev.name === "stats") renderStats(ev.data);
      return;
    }
    if (ev.severity) {        // gepushtes Event {ts,severity,category,source,message}
      appendStream(ev);
      addThreat(ev);
      addEvent(ev);
    }
  }

  // ---------- Stats-Polling ----------
  function pollStats() {
    if (window.aegis && typeof window.aegis.cmd === "function") {
      try { window.aegis.cmd(JSON.stringify({ name: "stats", args: {} })); } catch (e) {}
    }
  }

  // ---------- Controls ----------
  function wireControls() {
    const p = $("debug-pause");
    if (p) p.addEventListener("click", () => { paused = !paused; p.textContent = paused ? "▶" : "⏸"; });
    const c = $("debug-clear");
    if (c) c.addEventListener("click", () => { const l = $("debug-log"); if (l) l.textContent = ""; });
    const cp = $("debug-copy");
    if (cp) cp.addEventListener("click", () => {
      const l = $("debug-log"); if (!l) return;
      const txt = l.textContent || "";
      let ok = false;
      try {
        const ta = document.createElement("textarea");
        ta.value = txt; ta.style.position = "fixed"; ta.style.left = "-9999px";
        document.body.appendChild(ta); ta.focus(); ta.select();
        ok = document.execCommand("copy");
        document.body.removeChild(ta);
      } catch (e) {}
      if (!ok && navigator.clipboard) { try { navigator.clipboard.writeText(txt); ok = true; } catch (e) {} }
      const o = cp.textContent; cp.textContent = ok ? "✓" : "✗"; setTimeout(() => { cp.textContent = o; }, 900);
    });
    ["filter-severity", "filter-category", "filter-search"].forEach((id) => {
      const el = $(id); if (el) el.addEventListener("input", renderEventList);
    });
    ["debug-sev", "debug-source", "debug-search"].forEach((id) => {
      const el = $(id); if (el) { el.addEventListener("input", rerenderStream); el.addEventListener("change", rerenderStream); }
    });
    const tc = $("threats-clear");
    if (tc) tc.addEventListener("click", () => {
      const ol = $("threats-list");
      if (ol) ol.innerHTML = '<li class="empty">Noch keine Bedrohungen registriert.</li>';
    });
    setInterval(() => {
      const r = $("debug-rate");
      if (r) {
        const dt = (Date.now() - rateBase) / 1000;
        const rate = dt > 0 ? frameCount / dt : 0;
        r.textContent = rate.toFixed(1) + " ev/s · " + frameCount + " frames";
      }
    }, 2000);
  }

  // ---------- Bridge-Anbindung (eigene Slots; wartet auf window.aegis) ----------
  function attach() {
    if (!window.aegis || !window.aegis.eventReceived || !window.aegis.eventReceived.connect) {
      setTimeout(attach, 120);
      return;
    }
    window.aegis.eventReceived.connect((json) => {
      let ev; try { ev = JSON.parse(json); } catch (_) { return; }
      try { onEvent(ev); } catch (_) {}
    });
    if (window.aegis.stateChanged && window.aegis.stateChanged.connect) {
      window.aegis.stateChanged.connect((s) => {
        if (s === "connected") { if (!connectedAt) connectedAt = Date.now(); pollStats(); }
      });
    }
    if (!connectedAt) connectedAt = Date.now();
    pollStats();
    setInterval(pollStats, 5000);
    setInterval(tickUptime, 1000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wireControls);
  } else {
    wireControls();
  }
  attach();

  window.AegisDashboard = { refresh: pollStats, onEvent: onEvent };
})();
