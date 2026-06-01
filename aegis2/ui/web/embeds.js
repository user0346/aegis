/* AEGIS — Embeds: jede geöffnete Ansicht (Settings/Scan/Threats/…) wird zu einem bewegbaren,
   skalierbaren Panel mit Glow-Rahmen. Per Maus ziehen (Greifleiste oben) + an der Ecke
   skalieren; rastet an einem Raster ein; Position/Größe werden gemerkt; Doppelklick auf die
   Greifleiste = zurücksetzen. Der Rahmen leuchtet bei Hover/Auswahl und pulsiert, während
   AEGIS spricht/arbeitet (body.aegis-speaking, gesetzt von panels.js).
   Eigenständig, greift NICHT in das bestehende Layout ein, solange nichts bewegt wird. */
(function () {
  "use strict";
  var GRID = 16, MINW = 360, MINH = 220, PAD = 6;
  var snap = function (v) { return Math.round(v / GRID) * GRID; };
  var key = function (n) { return "aegis.embed." + n; };
  function load(n) { try { return JSON.parse(localStorage.getItem(key(n)) || "null"); } catch (e) { return null; } }
  function save(n, g) { try { localStorage.setItem(key(n), JSON.stringify(g)); } catch (e) {} }
  function clearG(n) { try { localStorage.removeItem(key(n)); } catch (e) {} }

  function clamp(g) {
    var w = Math.min(g.width, window.innerWidth - 2 * PAD);
    var h = Math.min(g.height, window.innerHeight - 2 * PAD);
    return {
      left: Math.max(PAD, Math.min(window.innerWidth - w - PAD, g.left)),
      top: Math.max(PAD, Math.min(window.innerHeight - h - PAD, g.top)),
      width: w, height: h
    };
  }
  function applyGeom(el, g) {
    g = clamp(g);
    el.classList.add("embed-floated");
    el.style.transform = "none";
    el.style.left = g.left + "px"; el.style.top = g.top + "px";
    el.style.width = g.width + "px"; el.style.height = g.height + "px";
  }
  function resetGeom(el) {
    el.classList.remove("embed-floated");
    el.style.left = el.style.top = el.style.width = el.style.height = el.style.transform = "";
  }
  function persist(el) {
    save(el.dataset.view, { left: parseInt(el.style.left, 10), top: parseInt(el.style.top, 10),
      width: el.offsetWidth, height: el.offsetHeight });
  }
  function floatFromCurrent(el) {               // aus der zentrierten Lage in feste left/top übernehmen
    var r = el.getBoundingClientRect();
    el.classList.add("embed-floated"); el.style.transform = "none";
    el.style.left = r.left + "px"; el.style.top = r.top + "px";
    el.style.width = r.width + "px"; el.style.height = r.height + "px";
  }
  function setActive(el) {
    var all = document.querySelectorAll(".embed-host.embed-active");
    for (var i = 0; i < all.length; i++) if (all[i] !== el) all[i].classList.remove("embed-active");
    el.classList.add("embed-active");
  }

  // ---- Ziehen ----
  var drag = null;
  function startDrag(e) {
    if (e.button !== 0) return;
    var el = e.currentTarget.closest(".view"); if (!el) return;
    floatFromCurrent(el);
    setActive(el); el.classList.add("embed-dragging");
    drag = { el: el, dx: e.clientX - el.offsetLeft, dy: e.clientY - el.offsetTop };
    document.addEventListener("mousemove", onDrag);
    document.addEventListener("mouseup", endDrag);
    e.preventDefault();
  }
  function onDrag(e) {
    if (!drag) return;
    var w = drag.el.offsetWidth, h = drag.el.offsetHeight;
    var left = snap(Math.max(PAD, Math.min(window.innerWidth - w - PAD, e.clientX - drag.dx)));
    var top = snap(Math.max(PAD, Math.min(window.innerHeight - h - PAD, e.clientY - drag.dy)));
    drag.el.style.left = left + "px"; drag.el.style.top = top + "px";
  }
  function endDrag() {
    if (!drag) return;
    drag.el.classList.remove("embed-dragging"); persist(drag.el);
    document.removeEventListener("mousemove", onDrag);
    document.removeEventListener("mouseup", endDrag); drag = null;
  }

  // ---- Skalieren ----
  var rez = null;
  function startResize(e) {
    if (e.button !== 0) return;
    var el = e.currentTarget.closest(".view"); if (!el) return;
    floatFromCurrent(el);
    setActive(el); el.classList.add("embed-dragging");
    rez = { el: el, x: e.clientX, y: e.clientY, w: el.offsetWidth, h: el.offsetHeight };
    document.addEventListener("mousemove", onResize);
    document.addEventListener("mouseup", endResize);
    e.preventDefault(); e.stopPropagation();
  }
  function onResize(e) {
    if (!rez) return;
    var w = snap(Math.max(MINW, rez.w + (e.clientX - rez.x)));
    var h = snap(Math.max(MINH, rez.h + (e.clientY - rez.y)));
    w = Math.min(w, window.innerWidth - rez.el.offsetLeft - PAD);
    h = Math.min(h, window.innerHeight - rez.el.offsetTop - PAD);
    rez.el.style.width = w + "px"; rez.el.style.height = h + "px";
  }
  function endResize() {
    if (!rez) return;
    rez.el.classList.remove("embed-dragging"); persist(rez.el);
    document.removeEventListener("mousemove", onResize);
    document.removeEventListener("mouseup", endResize); rez = null;
  }

  // ---- Mounten ----
  function pretty(name) { return (name || "").charAt(0).toUpperCase() + (name || "").slice(1) + "-Embed"; }
  function mount(el) {
    var name = el.dataset.view;
    if (!el.querySelector(":scope > .embed-grip")) {
      var grip = document.createElement("div");
      grip.className = "embed-grip";
      grip.innerHTML = '<span class="embed-dots">⠿</span><span class="embed-title"></span>' +
        '<span class="embed-hint">ziehen · Ecke = Größe · Doppelklick = zurücksetzen</span>';
      el.insertBefore(grip, el.firstChild);
      var rs = document.createElement("div"); rs.className = "embed-resize"; rs.title = "Größe ändern";
      el.appendChild(rs);
      grip.addEventListener("mousedown", startDrag);
      grip.addEventListener("dblclick", function () { clearG(name); resetGeom(el); });
      rs.addEventListener("mousedown", startResize);
    }
    var t = el.querySelector(":scope > .embed-grip .embed-title");
    if (t) t.textContent = pretty(name);
    el.classList.add("embed-host");
    var g = load(name);
    if (g) applyGeom(el, g); else resetGeom(el);
    setActive(el);
  }

  var _mo = null;
  function _observe() {                 // (Wieder-)Beobachten aller Views
    if (!_mo) return;
    var views = document.querySelectorAll(".view");
    for (var j = 0; j < views.length; j++) _mo.observe(views[j], { attributes: true, attributeFilter: ["class"] });
  }
  function safeMount(el) {
    // Observer WÄHREND des Mountens abkoppeln: unsere eigenen Klassen-Änderungen (embed-host/
    // embed-active) dürfen den Observer NICHT erneut auslösen -> keine Re-Entrancy/Endlosschleife.
    if (_mo) { try { _mo.disconnect(); } catch (e) {} }
    try { mount(el); } catch (e) {}
    _observe();
  }
  function init() {
    // Chat-Verlauf aus der backdrop-filter-Karte HERAUSLÖSEN -> position:fixed wirkt dann relativ
    // zum FENSTER (links am Rand), nicht relativ zur Karte (backdrop-filter = Containing-Block).
    try {
      if (document.body.classList.contains("mode-orb")) {
        var vh = document.getElementById("voice-history");
        var app = document.getElementById("app");
        if (vh && app && vh.parentElement !== app) app.appendChild(vh);
      }
    } catch (e) {}
    _mo = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var v = muts[i].target;
        if (v.classList && v.classList.contains("view") && v.classList.contains("is-active") &&
            v.dataset.view && v.dataset.view !== "voice") { safeMount(v); break; }
      }
    });
    _observe();
    var act = document.querySelectorAll(".view.is-active");
    for (var i = 0; i < act.length; i++) {
      if (act[i].dataset.view && act[i].dataset.view !== "voice") safeMount(act[i]);
    }
  }
  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
})();
