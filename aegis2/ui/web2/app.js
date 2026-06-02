/* AEGIS HUD — UI-Logik (eigener Code).
   - Lebendiger Orb: reagiert auf Voice-/System-Zustand (ruht/hoert/denkt/spricht/Alarm).
   - Bridge: QWebChannel im PyQt-WebView; ohne Bridge (Browser/Preview) -> Demo-Modus,
     damit der Orb sichtbar lebt und der Chat ein Beispiel zeigt.
*/
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };

  var ORB_LABEL = { idle: "Bereit", listening: "Höre zu …", thinking: "Denke nach …", speaking: "AEGIS spricht", alert: "Achtung" };
  var ORB_HINT = {
    idle: 'Sag <b>„Hey Jarvis“</b> — oder tippe unten',
    listening: "Ich höre …", thinking: "einen Moment …", speaking: "", alert: "Sieh dir die Bedrohungen an"
  };
  function setOrb(state) {
    var orb = $("orb"); if (!orb) return;
    orb.dataset.state = state;
    var s = $("orbState"); if (s) s.textContent = ORB_LABEL[state] || "Bereit";
    var h = $("orbHint"); if (h) h.innerHTML = (ORB_HINT[state] != null ? ORB_HINT[state] : "");
    setPulse(state === "alert" ? "alert" : (state === "idle" ? "idle" : "busy"));
  }
  function setPulse(state) { var p = $("pulse"); if (p) p.dataset.state = state; }

  function escapeHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function bubble(role, text) {
    var thread = document.querySelector(".thread"); if (!thread) return;
    var el = document.createElement("div");
    if (role === "user") { el.className = "msg-user"; el.textContent = text; }
    else { el.className = "msg-ai"; el.innerHTML = '<div class="who"><span class="mini"></span><span class="nm">AEGIS</span></div>' + escapeHtml(text); }
    thread.appendChild(el);
    var stage = document.querySelector(".stage"); if (stage) stage.scrollTop = stage.scrollHeight + 999;
  }

  /* ---------------- Bridge (QWebChannel) ---------------- */
  var bridged = false;
  function sendCmd(name, args) {
    if (window.aegis && typeof window.aegis.cmd === "function") {
      try { window.aegis.cmd(JSON.stringify({ name: name, args: args || {} })); } catch (e) {}
    }
  }
  function onEvent(ev) {
    if (!ev) return;
    var sev = (ev.severity || "").toString().toUpperCase();
    if (sev === "CRITICAL" || sev === "THREAT" || ev.category === "THREAT") {
      setOrb("alert"); setTimeout(function () { setOrb("idle"); }, 6000);
    }
    // Antwort-Text von AEGIS (Voice/Chat) -> als Blase zeigen
    if (ev.name === "voice.text" && ev.data && ev.data.text) { bubble("ai", ev.data.text); }
  }
  function onVoiceState(st) {
    if (st === "listening" || st === "thinking" || st === "speaking") setOrb(st);
    else setOrb("idle");
  }
  function wire() {
    var a = window.aegis; if (!a) return; bridged = true;
    if (a.eventReceived && a.eventReceived.connect) a.eventReceived.connect(function (j) { try { onEvent(JSON.parse(j)); } catch (e) {} });
    if (a.voiceState && a.voiceState.connect) a.voiceState.connect(onVoiceState);
  }
  function connect(tries) {
    tries = tries || 0;
    if (typeof QWebChannel !== "undefined" && window.qt && window.qt.webChannelTransport) {
      try { new QWebChannel(qt.webChannelTransport, function (ch) { window.aegis = ch.objects.aegis; wire(); }); return; } catch (e) {}
    }
    if (tries < 25) setTimeout(function () { connect(tries + 1); }, 60); else startDemo();
  }

  /* ---------------- Eingabe ---------------- */
  function submit() {
    var inp = document.querySelector(".inbar input"); if (!inp) return;
    var t = inp.value.trim(); if (!t) return; inp.value = "";
    var hero = document.querySelector(".hero"); if (hero) hero.style.display = "none";
    bubble("user", t);
    setOrb("thinking");
    if (bridged) { sendCmd("voice_text", { text: t }); }   // exakter Befehlsname gegen die laufende App final
    else { demoReply(t); }
  }
  function demoReply(t) {
    setTimeout(function () { setOrb("speaking"); bubble("ai", "Demo-Modus — im echten AEGIS antworte ich hier wirklich. Du sagtest: „" + t + "“"); }, 900);
    setTimeout(function () { setOrb("idle"); }, 3400);
  }

  /* ---------------- Demo (ohne Bridge): Orb lebt sichtbar ---------------- */
  var demoTimer = null;
  function startDemo() {
    if (demoTimer) return;
    var seq = ["listening", "thinking", "speaking", "idle"], i = 0;
    setOrb("listening");
    demoTimer = setInterval(function () { i++; setOrb(seq[i % seq.length]); }, 2600);
  }

  document.addEventListener("DOMContentLoaded", function () {
    setOrb("idle");
    var send = document.querySelector(".sendbtn"); if (send) send.addEventListener("click", submit);
    var inp = document.querySelector(".inbar input");
    if (inp) inp.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); submit(); } });
    connect();
  });
})();
