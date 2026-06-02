/* AEGIS Mobile-Bridge — ersetzt im Handy-Browser die Qt-QWebChannel-Bridge durch HTTP,
   damit die ECHTE PC-Oberflaeche 1:1 auf dem Handy laeuft (gleiche window.aegis-API).
   Token kommt aus ?t=<token> in der URL. Alle API-Aufrufe sind token-gesichert. */
(function () {
  "use strict";
  var T = new URLSearchParams(location.search).get("t") || "";
  function u(p) { return p + (p.indexOf("?") < 0 ? "?" : "&") + "t=" + encodeURIComponent(T); }
  function getJSON(p) { return fetch(u(p), { cache: "no-store" }).then(function (r) { return r.json(); }); }
  function postJSON(p, b) {
    return fetch(u(p), { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(b || {}) }).then(function (r) { return r.json(); });
  }

  // Qt-Signal-Nachbau: .connect(fn) registriert, .emit(...) ruft alle auf.
  function Signal() {
    var hs = [];
    return {
      connect: function (fn) { if (typeof fn === "function") hs.push(fn); },
      emit: function () { var a = arguments; for (var i = 0; i < hs.length; i++) { try { hs[i].apply(null, a); } catch (e) {} } }
    };
  }
  var S = {
    eventReceived: Signal(), stateChanged: Signal(), statsUpdated: Signal(),
    voiceState: Signal(), criticalAlert: Signal(), ollamaProgress: Signal(), fileSearchAsk: Signal()
  };

  var AEGIS = {
    // ---- Methoden (Qt-Stil: optionaler Callback als letztes Argument) ----
    state: function (cb) { if (cb) cb("connected"); return "connected"; },
    cmd: function (jsonStr, cb) {
      var d; try { d = JSON.parse(jsonStr); } catch (e) { d = {}; }
      var ref = Math.random().toString(36).slice(2, 10);
      postJSON("/api/exec", { name: d.name, args: d.args || {} }).then(function (res) {
        // Ergebnis als Event einspeisen — EXAKT wie der PC-Service: { t:"cmd_result", ok, name,
        // data, ref }. Das 't:"cmd_result"' ist Pflicht: panels.js' onEvent verarbeitet sonst
        // settings.get/scan.status/autonomy.* etc. gar nicht (Einstellungen wurden nicht gemerkt).
        try {
          S.eventReceived.emit(JSON.stringify({
            t: "cmd_result", ok: res.ok !== false,
            name: res.name || d.name, data: res.data, ref: ref
          }));
        } catch (e) {}
      }).catch(function () {});
      if (cb) cb(JSON.stringify({ ok: true, ref: ref }));
      return JSON.stringify({ ok: true, ref: ref });
    },
    voiceText: function (text) {
      S.voiceState.emit("state", "thinking");
      postJSON("/api/chat", { text: text }).then(function (res) {
        S.voiceState.emit("transcript", text);
        S.voiceState.emit("reply", res.reply || "");
        // UI-Aktionen vom Server nachspielen, damit Text-/Sprachbefehle die Oberflaeche am
        // Handy genauso steuern wie am PC (hide_chat/show_chat/switch_tab/hide_vision/show_vision).
        // Spiegelt die Zuordnung aus bridge.py:_voice_ui_cmd. Native PC-Aktionen
        // (minimize/restore/hide_window) gibt es am Handy nicht -> werden ignoriert.
        var ui = res.ui || [];
        for (var i = 0; i < ui.length; i++) {
          var a = ui[i] || {}, act = a.action;
          if (act === "switch_tab") S.voiceState.emit("tab", a.tab || "");
          else if (act === "hide_chat" || act === "show_chat" || act === "hide_vision") S.voiceState.emit("ui", act);
          else if (act === "show_vision") S.voiceState.emit("vision", a.img || "");
        }
        S.voiceState.emit("state", "idle");
      }).catch(function () { S.voiceState.emit("state", "idle"); });
    },
    voiceListen: function () {
      // Am Handy gibt es kein Hintergrund-Weckwort. Tipp-auf-Sprich per Browser-STT IST moeglich,
      // aber NUR im sicheren Kontext (HTTPS/localhost) — ueber http:// sperrt der Browser das Mikro.
      var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
      if (!window.isSecureContext || !SR) {
        S.voiceState.emit("reply", "Am Handy redest du per Tippen — schreib unten einfach deine Frage. " +
          "(Live-Sprache am Handy braucht eine HTTPS-Verbindung; das Weckwort »Hey Jarvis« läuft am PC.)");
        S.voiceState.emit("state", "idle");
        return;
      }
      try {
        var rec = new SR();
        rec.lang = "de-DE"; rec.interimResults = false; rec.maxAlternatives = 1;
        S.voiceState.emit("state", "listening");
        var got = false;
        rec.onresult = function (e) {
          got = true;
          var t = ((e.results[0] && e.results[0][0] && e.results[0][0].transcript) || "").trim();
          if (t) AEGIS.voiceText(t); else S.voiceState.emit("state", "idle");
        };
        rec.onerror = function () {
          S.voiceState.emit("reply", "Hab nichts verstanden — nochmal antippen oder unten tippen.");
          S.voiceState.emit("state", "idle");
        };
        rec.onend = function () { if (!got) S.voiceState.emit("state", "idle"); };
        rec.start();
      } catch (e) {
        S.voiceState.emit("reply", "Sprachaufnahme nicht möglich — tippe einfach unten.");
        S.voiceState.emit("state", "idle");
      }
    },
    stopSpeaking: function () {},
    ttsPreview: function (v) {},
    setWakeWord: function (on) { postJSON("/api/exec", { name: "settings.save", args: { wake_word_enabled: !!on } }).catch(function () {}); },
    wakeWordOn: function (cb) { if (cb) cb(false); },
    // Gespraechsmodus betrifft nur den Sprach-Loop am PC; am Handy (Tippen) ohne Wirkung,
    // aber die Einstellung wird trotzdem persistiert, damit der Schalter konsistent bleibt.
    setConversationMode: function (on) { postJSON("/api/exec", { name: "settings.save", args: { conversation_followup: !!on } }).catch(function () {}); },
    conversationModeOn: function (cb) { if (cb) cb(true); },
    memoryGet: function (cb) { getJSON("/api/memory").then(function (d) { if (cb) cb(JSON.stringify(d)); }).catch(function () { if (cb) cb("{}"); }); },
    ollamaStatus: function (cb) { getJSON("/api/ollama").then(function (d) { if (cb) cb(JSON.stringify(d)); }).catch(function () { if (cb) cb('{"installed":true,"running":true}'); }); },
    ollamaStart: function () {},
    ollamaInstall: function () {},
    // ---- Signale ----
    eventReceived: S.eventReceived, stateChanged: S.stateChanged, statsUpdated: S.statsUpdated,
    voiceState: S.voiceState, criticalAlert: S.criticalAlert, ollamaProgress: S.ollamaProgress, fileSearchAsk: S.fileSearchAsk
  };

  // Qt-Globals faken -> app.js' setupChannel() (wartet auf QWebChannel + qt.webChannelTransport)
  // laeuft unveraendert und bekommt unsere AEGIS-Bruecke.
  window.qt = { webChannelTransport: { send: function () {}, onmessage: null } };
  window.QWebChannel = function (transport, cb) { try { cb({ objects: { aegis: AEGIS } }); } catch (e) {} };

  // Periodischer Push wie am PC: Verbindung halten + neue Events einspeisen (nach ts, keine Dubletten).
  var lastTs = 0;
  function poll() {
    S.stateChanged.emit("connected");
    getJSON("/api/events").then(function (d) {
      var evs = (d && d.events) || [];
      // /api/events liefert neueste zuerst -> in Reihenfolge alt->neu einspeisen, nur neue ts.
      var fresh = [];
      for (var i = 0; i < evs.length; i++) { if ((evs[i].ts || 0) > lastTs) fresh.push(evs[i]); }
      fresh.sort(function (a, b) { return (a.ts || 0) - (b.ts || 0); });
      for (var j = 0; j < fresh.length; j++) {
        if ((fresh[j].ts || 0) > lastTs) lastTs = fresh[j].ts || 0;
        try { S.eventReceived.emit(JSON.stringify(fresh[j])); } catch (e) {}
      }
    }).catch(function () { S.stateChanged.emit("disconnected"); });
  }
  setTimeout(function () { poll(); setInterval(poll, 4000); }, 200);

  // Hinweis am Handy ehrlich machen: das Weckwort „Hey Jarvis" gibt es nur am PC.
  // Hier den irrefuehrenden Untertitel auf „tippen" umstellen (mehrfach versuchen, bis
  // die echte PC-Oberflaeche geladen + gerendert ist).
  function fixHint() {
    var hit = false;
    var nodes = document.querySelectorAll('.view[data-view="voice"] .muted, .voice-state .muted, #voice-substatus');
    for (var i = 0; i < nodes.length; i++) {
      if (/Hey\s*Jarvis/i.test(nodes[i].textContent || "")) {
        nodes[i].textContent = "Tippe unten, um mit AEGIS zu reden.";
        hit = true;
      }
    }
    return hit;
  }
  // Tipp-auf-Sprich am Handy nutzbar machen: die VOICE-Pille (am PC nur ein Weckwort-Status)
  // tappbar machen UND einen klaren Mikro-Knopf in die Eingabezeile setzen. Beide rufen
  // voiceListen() -> Browser-STT (funktioniert im sicheren Kontext / HTTPS).
  function setupVoiceUI() {
    var pill = document.getElementById("voice-pill");
    if (pill && !pill.dataset.mBound) {
      pill.dataset.mBound = "1";
      pill.style.cursor = "pointer";
      pill.title = "Antippen und sprechen";
      pill.addEventListener("click", function () { try { AEGIS.voiceListen(); } catch (e) {} });
    }
    var row = document.querySelector(".voice-input");
    if (row && !document.getElementById("m-mic")) {
      var b = document.createElement("button");
      b.id = "m-mic"; b.className = "btn"; b.type = "button";
      b.textContent = "🎤"; b.title = "Antippen und sprechen";
      b.addEventListener("click", function () { try { AEGIS.voiceListen(); } catch (e) {} });
      var send = document.getElementById("voice-send");
      if (send && send.parentNode === row) row.insertBefore(b, send); else row.appendChild(b);
    }
    return !!(pill && pill.dataset.mBound && document.getElementById("m-mic"));
  }

  var _ht = 0;
  var _hi = setInterval(function () {
    fixHint();
    if (setupVoiceUI() || ++_ht > 16) clearInterval(_hi);
  }, 700);
})();
