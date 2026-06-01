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
        S.voiceState.emit("state", "idle");
      }).catch(function () { S.voiceState.emit("state", "idle"); });
    },
    voiceListen: function () {
      // Freihaendige Spracheingabe laeuft am PC (Mikro/Weckwort). Am Handy: tippen.
      S.voiceState.emit("reply", "Sprich am PC mit „Hey Jarvis“ — hier am Handy tippe einfach.");
      S.voiceState.emit("state", "idle");
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
})();
