(function () {
  "use strict";
  console.log("[AEGIS] app.js loaded");

  // Orb-minimal (Single-Screen): Home = Orb + Chat (data-view="voice"), alle anderen
  // Ansichten erscheinen als einblendbares Overlay ueber dem Orb. Aktiv nur, wenn
  // <body class="mode-orb">. Ohne die Klasse bleibt das klassische Tab-Verhalten.
  var HOME = "voice";
  function isOrb() { return document.body.classList.contains("mode-orb"); }

  function sizeBrain(name) {
    try {
      if (window.AegisBrain && typeof window.AegisBrain.sizeFor === "function") {
        window.AegisBrain.sizeFor(name || HOME);
      }
    } catch (e) {}
  }

  // Header-Hoehe in --hdr spiegeln, damit Overlays exakt darunter beginnen
  // (das Dock kann auf schmalen Fenstern umbrechen -> Hoehe variiert).
  function syncHeader() {
    try {
      var h = document.querySelector(".topbar");
      if (h) document.documentElement.style.setProperty("--hdr", h.offsetHeight + "px");
    } catch (e) {}
  }
  window.addEventListener("resize", syncHeader);

  // Backdrop + Schliessen-Knopf einmalig anlegen (nur Orb-Modus).
  function ensureChrome() {
    syncHeader();
    if (document.getElementById("overlay-backdrop")) return;
    // WICHTIG: in #app einhaengen, NICHT in body. #app hat z-index:1 (eigener Stacking-
    // Kontext); ein an body gehaengter Backdrop (z80) wuerde sonst ueber dem GANZEN #app
    // (inkl. der Overlay-Panels z81) liegen und sie abdunkeln. Im selben Kontext gilt:
    // Backdrop 80 < Panel 81 -> Panel bleibt hell, nur der Hintergrund dunkelt ab.
    var host = document.getElementById("app") || document.body;
    var bd = document.createElement("div");
    bd.id = "overlay-backdrop";
    bd.className = "overlay-backdrop";
    bd.addEventListener("click", goHome);
    host.appendChild(bd);
    var cl = document.createElement("button");
    cl.id = "overlay-close";
    cl.className = "overlay-close";
    cl.type = "button";
    cl.title = "Schliessen (Esc)";
    cl.setAttribute("aria-label", "Schliessen");
    cl.textContent = "✕";   // ✕
    cl.addEventListener("click", goHome);
    host.appendChild(cl);
  }

  // Zurueck zur Orb-Heimansicht: Home aktiv, alle Overlays zu.
  function goHome() {
    document.querySelectorAll(".view").forEach(function (v) {
      v.classList.toggle("is-active", v.dataset.view === HOME);
    });
    document.querySelectorAll(".tab").forEach(function (b) {
      b.classList.toggle("is-active", b.dataset.tab === HOME);
    });
    document.body.classList.remove("overlay-open");
    sizeBrain(HOME);
  }

  function activateTab(name) {
    if (isOrb()) {
      if (name === HOME) { goHome(); return; }
      ensureChrome();
      // Overlay oeffnen: Zielansicht aktiv, Home bleibt als Hintergrund sichtbar.
      document.querySelectorAll(".view").forEach(function (v) {
        if (v.dataset.view === HOME) return;            // Home nie deaktivieren
        v.classList.toggle("is-active", v.dataset.view === name);
      });
      document.querySelectorAll(".tab").forEach(function (b) {
        b.classList.toggle("is-active", b.dataset.tab === name);
      });
      document.body.classList.add("overlay-open");
    } else {
      // Klassisches Tab-Verhalten (Fallback ohne mode-orb).
      document.querySelectorAll(".tab").forEach(function (b) {
        b.classList.toggle("is-active", b.dataset.tab === name);
      });
      document.querySelectorAll(".view").forEach(function (v) {
        v.classList.toggle("is-active", v.dataset.view === name);
      });
    }
    try {
      if (window.AegisBrain && typeof window.AegisBrain.sizeFor === "function") { window.AegisBrain.sizeFor(name); }
      if (window.AegisSentinel && name === "sentinel" && typeof window.AegisSentinel.onShow === "function") { window.AegisSentinel.onShow(); }
      if (window.AegisPanels && typeof window.AegisPanels[name] === "function") { window.AegisPanels[name](); }
    } catch (e) {}
  }

  document.querySelectorAll(".tab").forEach(function (btn) {
    btn.addEventListener("click", function () { activateTab(btn.dataset.tab); });
  });

  // Esc schliesst ein offenes Overlay -> zurueck zur Orb-Heimansicht.
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && isOrb() && document.body.classList.contains("overlay-open")) goHome();
  });

  function setConnState(state) {
    var pill = document.getElementById("conn-pill");
    if (!pill) return;
    if (state === "connected") {
      pill.textContent = "CONNECTED";
      pill.classList.remove("pill-warn", "pill-mute");
      pill.classList.add("pill-ok");
    } else {
      pill.textContent = "DISCONNECTED";
      pill.classList.remove("pill-ok");
      pill.classList.add("pill-warn");
    }
  }

  function setupChannel(cb) {
    if (typeof QWebChannel === "undefined") { setTimeout(function () { setupChannel(cb); }, 50); return; }
    if (!window.qt || !window.qt.webChannelTransport) { setTimeout(function () { setupChannel(cb); }, 50); return; }
    new QWebChannel(qt.webChannelTransport, function (channel) {
      window.aegis = channel.objects.aegis;
      console.log("[AEGIS] QWebChannel registered, keys=", Object.keys(window.aegis || {}));
      cb && cb();
    });
  }

  function wireBridge() {
    if (!window.aegis) return;
    if (window.aegis.state) {
      try { window.aegis.state(function (s) { console.log("[AEGIS] initial state:", s); setConnState(s || "disconnected"); }); } catch (e) {}
    }
    if (window.aegis.stateChanged && window.aegis.stateChanged.connect) {
      window.aegis.stateChanged.connect(function (s) { console.log("[AEGIS] stateChanged:", s); setConnState(s); });
    }
    if (window.aegis.eventReceived && window.aegis.eventReceived.connect) {
      window.aegis.eventReceived.connect(function (json) {
        var ev;
        try { ev = JSON.parse(json); } catch (_) { return; }
        if (window.AegisBrain && typeof window.AegisBrain.activateForEvent === "function") { try { window.AegisBrain.activateForEvent(ev); } catch (_) {} }
        if (window.AegisSentinel && typeof window.AegisSentinel.onEvent === "function") { try { window.AegisSentinel.onEvent(ev); } catch (_) {} }
      });
    }
  }

  setupChannel(function () { wireBridge(); });

  // Orb-Modus: beim Start sauber die Heimansicht zeigen (kein Dashboard-Overlay-Aufblitzen).
  if (isOrb()) { ensureChrome(); try { goHome(); } catch (e) {} }

  window.AegisApp = { activateTab: activateTab, setConnState: setConnState, goHome: goHome };
})();
