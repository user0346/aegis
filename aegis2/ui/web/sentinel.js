/* ============================================================
   AEGIS V2 — Sentinel Panel (Driver / USB / Keylog)
   ------------------------------------------------------------
   Datenquellen via IPC:
       driver.list / driver.rescan / driver.trust
       usb.list    / usb.block_vid_pid / usb.unblock_vid_pid
       keylog.suspects / keylog.add_name / keylog.remove_name

   Updates: passiv via eventReceived (DriverScanner/UsbWatcher/
   KeylogWatcher pushen Events, sentinel re-fetched dann).
   Aktiv: einmal beim Tab-Wechsel + alle 30s wenn Tab sichtbar.
   ============================================================ */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  // ----- IPC helper -----
  function cmd(name, args, cb) {
    if (!window.aegis || typeof window.aegis.cmd !== "function") return;
    try {
      window.aegis.cmd(JSON.stringify({ name: name, args: args || {} }));
    } catch (e) { console.warn("sentinel cmd", e); }
  }

  // ----- State -----
  let visible = false;
  let pollTimer = null;
  // Cache of latest cmd-result payloads (keyed by cmd name)
  const cache = { driver: [], usb: [], keylog: [] };

  // ----- Rendering -----
  function renderDriver() {
    const tbody = $("driver-tbody");
    if (!tbody) return;
    const items = cache.driver;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">' +
        'Keine ungewöhnlichen Driver. (Erster Scan läuft 3 Min nach Service-Start.)' +
        '</td></tr>';
      return;
    }
    tbody.innerHTML = items.slice(0, 100).map((r) => {
      const status = (r.status || r.message || "").toString();
      const sev = (r.severity || "").toString();
      const cls = sev === "CRITICAL" ? "row-bad"
                : sev === "WARN"     ? "row-warn"
                : "";
      const meta = r.metadata || {};
      return `<tr class="${cls}">
        <td>${escape(meta.name || r.name || "?")}</td>
        <td><span class="badge badge-${badgeClass(status)}">${escape(status)}</span></td>
        <td class="mono">${escape(truncate(meta.signer || "—", 38))}</td>
        <td>${meta.started ? "running" : "stopped"}</td>
      </tr>`;
    }).join("");
  }

  function renderUsb() {
    const tbody = $("usb-tbody");
    if (!tbody) return;
    const items = cache.usb;
    $("usb-count").textContent = `${items.length} devices`;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">Noch keine Devices in Baseline.</td></tr>';
      return;
    }
    tbody.innerHTML = items.slice(0, 100).map((r) => {
      const vid = (r.vid || r.VID || "—");
      const pid = (r.pid || r.PID || "—");
      const cls = (r.Class || r.cls || "");
      const name = r.Name || r.name || "(unknown)";
      const vp = `${vid}:${pid}`;
      return `<tr>
        <td>${escape(name)}</td>
        <td>${escape(cls)}</td>
        <td class="mono">${escape(vp)}</td>
        <td><button class="btn-tiny" data-vid="${vid}" data-pid="${pid}">Block</button></td>
      </tr>`;
    }).join("");
    tbody.querySelectorAll("button[data-vid]").forEach((btn) => {
      btn.addEventListener("click", () => {
        cmd("usb.block_vid_pid", { vid: btn.dataset.vid, pid: btn.dataset.pid });
        setTimeout(refresh, 500);
      });
    });
  }

  function renderKeylog() {
    const ul = $("keylog-tbody");
    if (!ul) return;
    const items = cache.keylog;
    $("keylog-suspect-count").textContent = `${items.length} suspects`;
    if (!items.length) {
      ul.innerHTML = '<li class="muted">Keine Verdachts-Prozesse erfasst.</li>';
      return;
    }
    ul.innerHTML = items.slice(0, 50).map((s) =>
      `<li class="suspect-row mono">${escape(s)}</li>`
    ).join("");
  }

  // ----- Refresh -----
  function refresh() {
    cmd("driver.list",     { limit: 50 });
    cmd("usb.list",        {});
    cmd("keylog.suspects", {});
  }

  // ----- Event handlers -----
  function onEvent(ev) {
    if (!ev) return;
    const src = (ev.source || "").toString();
    // Driver / USB / Keylog events -> refresh after small delay
    if (src === "DriverScanner" || src === "UsbWatcher" || src === "KeylogWatcher") {
      if (visible) setTimeout(refresh, 300);
    }
    // cmd_result for our queries
    if (ev.t === "cmd_result" && ev.ok && ev.data) {
      const name = (ev.name || "");
      if (name === "driver.list") {
        cache.driver = (ev.data.items || []);
        renderDriver();
      } else if (name === "usb.list") {
        cache.usb = (ev.data.devices || []);
        renderUsb();
      } else if (name === "keylog.suspects") {
        cache.keylog = (ev.data.suspects || []);
        renderKeylog();
      }
    }
  }

  function onShow() {
    visible = true;
    refresh();
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => { if (visible) refresh(); }, 30000);
  }
  function onHide() {
    visible = false;
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }
  // Hook tab change
  document.querySelectorAll(".tab").forEach((b) => {
    b.addEventListener("click", () => {
      if (b.dataset.tab === "sentinel") onShow();
      else onHide();
    });
  });

  // ----- Button handlers -----
  document.addEventListener("DOMContentLoaded", () => {
    const reScan = $("driver-rescan");
    if (reScan) reScan.addEventListener("click", () => {
      cmd("driver.rescan", {});
      setTimeout(refresh, 2000);
    });
    const usbAdd = $("usb-block-add");
    if (usbAdd) usbAdd.addEventListener("click", () => {
      const vid = ($("usb-block-vid").value || "").trim().toUpperCase();
      const pid = ($("usb-block-pid").value || "").trim().toUpperCase();
      if (!vid || !pid) return;
      cmd("usb.block_vid_pid", { vid: vid, pid: pid });
      $("usb-block-vid").value = "";
      $("usb-block-pid").value = "";
    });
    const klogAdd = $("keylog-add-btn");
    if (klogAdd) klogAdd.addEventListener("click", () => {
      const n = ($("keylog-add-name").value || "").trim();
      if (!n) return;
      cmd("keylog.add_name", { name: n });
      $("keylog-add-name").value = "";
    });
  });

  // ----- Helpers -----
  function escape(s) {
    return String(s || "").replace(/[&<>"']/g, (c) =>
      ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[c]));
  }
  function truncate(s, n) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  function badgeClass(status) {
    if (status === "Valid")        return "ok";
    if (status === "NotSigned")    return "bad";
    if (status === "HashMismatch") return "bad";
    if (status === "Expired")      return "warn";
    if (status === "NotTrusted")   return "warn";
    return "";
  }

  // ----- Public API (consumed by app.js event-router + tab activation) -----
  window.AegisSentinel = { onShow: onShow, onHide: onHide, onEvent: onEvent };
})();
