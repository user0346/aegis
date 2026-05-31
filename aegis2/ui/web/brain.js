/* ============================================================
   AEGIS Cognition Brain v6 — "Arc-Reactor" Neural AI Core.
   ------------------------------------------------------------
   Ein lebendiger, glühender Jarvis-/Iron-Man-Energiekern,
   gerendert komplett in Canvas 2D (kein WebGL, kein Shader-Compile,
   keine externen Abhängigkeiten — läuft offline in jeder WebView).

   Aufbau der Schichten (von hinten nach vorn):
     1. weicher Außen-Halo (mehrstufiger Radial-Gradient)
     2. orbitierendes neuronales Partikelfeld (gedeckelt, wirbelnd)
     3. zwei gegenläufige, segmentierte HUD-Ringe (Reaktor-Spulen)
     4. dünne Tick-/Skalen-Ringe (HUD-Detail)
     5. pulsierender Plasma-Kern mit weiß-heißem Zentrum
     6. Audio-artige Ripple-Wellen (beim Sprechen / bei Events)

   ZUSTANDSREAKTIV (echte AEGIS-Signale, keine Fake-Events):
     - idle        -> langsames Atmen, AEGIS-Cyan
     - thinking    -> schneller wirbelnd, heller, energetischer
     - listening   -> sanftes Pulsieren (Voice-Eingang)
     - speaking    -> Ripple-Wellen nach außen (Voice-Ausgang)
     - threat      -> Farbe -> Amber (WARN) / Rot (CRITICAL) + harter Puls

   ROBUSTHEIT: Es gibt NIE einen throw und nie einen schwarzen Canvas.
   Fehlt der 2D-Context, schaltet die Klasse still ab. Render pausiert,
   wenn der Canvas unsichtbar oder der Tab versteckt ist.

   Public API (1:1 KOMPATIBEL — von app.js + panels.js konsumiert):
     window.AegisBrain = { init, activateForEvent, thinking, setMood, sizeFor }
       - app.js   : AegisBrain.sizeFor(), AegisBrain.activateForEvent(ev)
       - panels.js: AegisBrain.activateForEvent({category:"VOICE",source:st,...})
                    AegisBrain.thinking(true|false)
   ============================================================ */
"use strict";
(function () {

  /* ---- Farb-Paletten (RGB 0..255) ------------------------------------ */
  const COL_IDLE   = [143, 209, 255];   // AEGIS-Cyan (Ruhe)
  const COL_THINK  = [120, 200, 255];   // helleres Cyan beim Denken
  const COL_VOICE  = [130, 220, 255];   // Stimme
  const COL_THREAT = [249, 115, 115];   // Bedrohung (Rot)
  const COL_WARN   = [250, 204,  21];   // Warnung (Gelb/Amber)
  const COL_QUAR   = [181, 141, 255];   // Quarantäne (Violett)

  // Event-Kategorie -> Akzentfarbe (nur fürs Tönen des Kerns).
  function catColor(cat) {
    switch (cat) {
      case "TAMPER":     return COL_THREAT;
      case "QUARANTINE": return COL_QUAR;
      case "USB":        return [255, 200, 120];
      case "URL":
      case "DNS":        return [200, 170, 255];
      case "PROCESS":
      case "THREAT":     return [150, 230, 180];
      default:           return null;
    }
  }
  // Severity -> Farbe (überschreibt Kategorie bei echter Gefahr).
  function sevColor(s) {
    if (s === "CRITICAL" || s === "THREAT") return COL_THREAT;
    if (s === "WARN")  return COL_WARN;
    if (s === "QUARANTINE") return COL_QUAR;
    return null;
  }

  function lerp(a, b, t) { return a + (b - a) * t; }
  function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }
  function rgba(c, a) {
    return "rgba(" + (c[0] | 0) + "," + (c[1] | 0) + "," + (c[2] | 0) + "," +
           clamp(a, 0, 1).toFixed(3) + ")";
  }
  // Mische Farbe Richtung Weiß (heißer Kern).
  function toward(c, target, t) {
    return [lerp(c[0], target[0], t), lerp(c[1], target[1], t), lerp(c[2], target[2], t)];
  }
  const WHITE = [255, 255, 255];

  /* ====================================================================
     Brain — das öffentliche Objekt. API bleibt unverändert.
     ==================================================================== */
  const Brain = {
    canvas: null,
    ctx: null,
    mode: "none",          // "canvas2d" | "none"
    visible: false,
    running: false,
    lastTs: 0,
    startTs: 0,

    // Backing-Store-Maße in CSS-Pixeln (nach DPR-Transform).
    W: 0, H: 0, cx: 0, cy: 0, unit: 0,

    // ---- logischer Zustand (von der API gesetzt, sanft interpoliert) ----
    state: 0,              // 0=idle .. 1=thinking (Ziel: stateTarget)
    stateTarget: 0,
    pulse: 0,              // momentane Puls-Stärke (Voice / Event)
    threat: 0,             // 0..1 Bedrohungs-Anteil (Ziel: threatTarget)
    threatTarget: 0,
    spin: 0,               // akkumulierter Rotationswinkel (Ringe/Partikel)
    col: COL_IDLE.slice(), // aktuelle Farbe (interpoliert)
    colTarget: COL_IDLE.slice(),
    thinkingOn: false,

    // ---- Partikel & Ripples ----
    particles: [],
    ripples: [],           // {r, a} expandierende Audio-Wellen

    // ---- Overlay-/Substate-Status ----
    lastEvent: null,
    lastEventTs: 0,
    voiceState: null,      // "listening" | "speaking" | "thinking" | null
    voiceStateTs: 0,

    /* ---------------------------------------------------------------- */
    init(canvas) {
      if (!canvas) return;
      this.canvas = canvas;
      this.startTs = this._now();
      this.lastTs = this.startTs;

      // 2D-Context holen — bei Fehlen still abschalten (nie crashen).
      try {
        const ctx = canvas.getContext("2d");
        if (ctx) { this.ctx = ctx; this.mode = "canvas2d"; }
      } catch (e) { this.mode = "none"; }

      // Resize beobachten.
      try {
        const ro = new ResizeObserver(() => this._resize());
        ro.observe(canvas);
      } catch (e) { window.addEventListener("resize", () => this._resize()); }
      this._resize();

      // Sichtbarkeit -> Render pausieren wenn unsichtbar.
      try {
        const io = new IntersectionObserver(
          (es) => es.forEach(en => { this.visible = en.isIntersecting; }),
          { threshold: 0.02 });
        io.observe(canvas);
      } catch (e) { this.visible = true; }

      // Render-Loop.
      this.running = true;
      const tick = (ts) => {
        if (!this.running) return;
        const dt = Math.min(80, ts - this.lastTs);
        this.lastTs = ts;
        if (this.visible && !document.hidden && this.mode === "canvas2d") {
          this._step(dt);
          this._render(ts);
          this._overlay();
        }
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    },

    /* ===== Öffentliche API (Verträge 1:1) =========================== */

    // Echtes AEGIS-Event -> Kern reagiert. ev.severity / ev.category /
    // ev.source steuern Farbe, Puls und Bedrohungs-Anteil.
    activateForEvent(ev) {
      if (!ev) return;
      const cat = (ev.category || "SYSTEM").toString().toUpperCase();
      const sev = (ev.severity || "INFO").toString().toUpperCase();

      // Energie/Erregung kurz anheben.
      const power = sev === "CRITICAL" ? 1.0
                  : sev === "THREAT"   ? 0.95
                  : sev === "QUARANTINE" ? 0.8
                  : sev === "WARN"     ? 0.65
                  : 0.45;
      this.stateTarget = Math.max(this.stateTarget, Math.min(1, power));
      this.pulse = Math.min(1.4, this.pulse + power * 0.9);
      this._emitRipple(power);   // jeder echte Impuls wirft eine Welle

      // Bedrohungs-Anteil bei echter Gefahr hochziehen (Farbe -> Rot).
      const danger = (sev === "CRITICAL" || sev === "THREAT" || cat === "TAMPER");
      if (danger) this.threatTarget = 1.0;
      else if (sev === "WARN") this.threatTarget = Math.max(this.threatTarget, 0.45);

      // Zielfarbe: Severity schlägt Kategorie schlägt Voice/Idle.
      const sc = sevColor(sev) || catColor(cat);
      if (sc) this.colTarget = sc.slice();
      else if (cat === "VOICE") this.colTarget = COL_VOICE.slice();

      // Voice-Substate (panels.js liefert source = "listening"/"speaking"/...).
      if (cat === "VOICE") {
        const src = (ev.source || "").toString().toLowerCase();
        if (src === "listening" || src === "speaking" || src === "thinking") {
          this.voiceState = src;
          this.voiceStateTs = this._now();
          if (src === "speaking") this._emitRipple(0.7);
        }
      }

      // Overlay-Info.
      this.lastEvent = {
        cat: cat,
        src: (ev.source || "").toString(),
        sev: sev,
        danger: danger
      };
      this.lastEventTs = this._now();
    },

    // panels.js: B.thinking(true|false) je Voice-Zustand.
    thinking(on) {
      this.thinkingOn = !!on;
      if (on) {
        this.stateTarget = Math.max(this.stateTarget, 0.85);
        this.pulse = Math.min(1.4, this.pulse + 0.5);
      } else {
        // zurück Richtung Ruhe — die Interpolation macht den sanften Übergang.
        this.stateTarget = 0.0;
        this.threatTarget = 0.0;
        this.colTarget = COL_IDLE.slice();
        this.voiceState = null;
      }
    },

    // No-op (API-Kompatibilität — Stimmung wird aus Events/State abgeleitet).
    setMood() {},

    // app.js ruft das beim Tab-/Größenwechsel auf.
    sizeFor() { try { this._resize(); } catch (e) {} },

    /* ===== Interna =================================================== */

    _now() { return (typeof performance !== "undefined" ? performance.now() : Date.now()); },

    // Eine expandierende Ripple-Welle (Voice-Ausgang / Event-Impuls).
    _emitRipple(strength) {
      if (this.ripples.length > 6) return;     // gedeckelt
      this.ripples.push({ r: 0.30, a: clamp(0.35 + 0.35 * strength, 0, 0.8) });
    },

    // Partikelfeld erzeugen/anpassen (Anzahl skaliert leicht mit Größe, gedeckelt).
    _ensureParticles() {
      const want = clamp(Math.round((this.unit || 120) * 0.55), 48, 96);
      const p = this.particles;
      while (p.length < want) {
        // Polar-Verteilung: meist nahe der Hülle, manche driften nach außen.
        const ang = Math.random() * Math.PI * 2;
        const rad = 0.30 + Math.random() * 0.62;     // relativ zu unit
        p.push({
          ang: ang,
          rad: rad,
          baseRad: rad,
          // individuelle Orbit-Geschwindigkeit (Vorzeichen = Richtung)
          spd: (0.10 + Math.random() * 0.5) * (Math.random() < 0.5 ? 1 : -1),
          // radiales "Wabern"
          wob: Math.random() * Math.PI * 2,
          wobSpd: 0.4 + Math.random() * 1.1,
          size: 0.6 + Math.random() * 1.7,
          tw: Math.random() * Math.PI * 2       // Twinkle-Phase
        });
      }
      if (p.length > want) p.length = want;
    },

    // Sanfte Zustands-Interpolation + Abklingen von Puls/Energie.
    _step(dt) {
      const k = dt / 33;                       // ~1 pro 33ms-Frame
      const tsec = dt / 1000;

      // Energie folgt dem Ziel — SANFT interpoliert.
      const rate = this.stateTarget > this.state ? 0.05 : 0.03;
      this.state  = lerp(this.state,  this.stateTarget,  Math.min(1, rate * k));
      // Bedrohung sanfter ein-/ausblenden.
      this.threat = lerp(this.threat, this.threatTarget, Math.min(1, 0.035 * k));

      // Puls klingt ab (Voice-/Event-Impulse sind kurz).
      this.pulse *= Math.pow(0.96, k);
      if (this.pulse < 0.01) this.pulse = 0;

      // Aktiver Voice-Substate hält einen Grundpuls.
      const vAge = this._now() - this.voiceStateTs;
      if (this.voiceState && vAge < 4000) {
        this.pulse = Math.max(this.pulse, this.voiceState === "speaking" ? 0.6 : 0.45);
        // beim Sprechen kontinuierlich sanfte Wellen nachschieben
        if (this.voiceState === "speaking" && Math.random() < 0.04 * k) this._emitRipple(0.5);
      }

      // Energie/Erregung von selbst Richtung 0, wenn kein thinking aktiv ist.
      if (!this.thinkingOn && this.stateTarget > 0) {
        this.stateTarget *= Math.pow(0.97, k);
        if (this.stateTarget < 0.02) this.stateTarget = 0;
      }
      // Bedrohung ebenso langsam zurücknehmen.
      if (this.threatTarget > 0) {
        this.threatTarget *= Math.pow(0.985, k);
        if (this.threatTarget < 0.02) this.threatTarget = 0;
      }

      // Farbe interpolieren (RGB) — sanfter Übergang Cyan->Amber->Rot.
      for (let i = 0; i < 3; i++)
        this.col[i] = lerp(this.col[i], this.colTarget[i], Math.min(1, 0.04 * k));

      // Globale Rotation — idle langsam, thinking schneller, threat treibt an.
      const spinSpeed = 0.10 + this.state * 0.55 + this.threat * 0.85;
      this.spin += spinSpeed * tsec;

      // Partikel bewegen.
      this._ensureParticles();
      const swirl = 1 + this.state * 1.8 + this.threat * 2.4;   // Wirbel-Tempo
      const p = this.particles;
      for (let i = 0; i < p.length; i++) {
        const pt = p[i];
        pt.ang += pt.spd * swirl * tsec;
        pt.wob += pt.wobSpd * tsec * (1 + this.state);
        pt.tw  += (2.5 + this.state * 3) * tsec;
        // radiales Wabern + bei Puls leicht nach außen "atmen"
        pt.rad = pt.baseRad + Math.sin(pt.wob) * 0.04 + this.pulse * 0.05;
      }

      // Ripples expandieren & verblassen.
      const rp = this.ripples;
      for (let i = rp.length - 1; i >= 0; i--) {
        rp[i].r += (0.55 + this.threat * 0.5) * tsec;
        rp[i].a *= Math.pow(0.55, tsec);       // schnell ausklingen
        if (rp[i].a < 0.02 || rp[i].r > 1.4) rp.splice(i, 1);
      }
    },

    _render(ts) {
      const ctx = this.ctx; if (!ctx) return;
      const W = this.W, H = this.H, cx = this.cx, cy = this.cy, u = this.unit;
      if (W <= 0 || H <= 0 || u <= 0) return;

      const tsec = (ts - this.startTs) / 1000;
      const c = this.col;
      const hot = toward(c, WHITE, 0.6);       // heißer Kern (fast weiß)

      // Atem-/Pulsfaktoren (ruhig gehalten).
      const breath = 0.5 + 0.5 * Math.sin(tsec * (0.5 + this.state * 0.6));
      const pulse  = clamp(this.pulse, 0, 1) * (0.5 + 0.5 * Math.sin(tsec * (3.0 + this.threat * 4.0)));
      // Threat-Notfall-Blitz: bei hoher Bedrohung harter zusätzlicher Puls.
      const alarm  = this.threat > 0.25 ? (0.5 + 0.5 * Math.sin(tsec * 7.0)) * this.threat : 0;

      const coreR = u * (0.30 + 0.018 * breath + 0.05 * this.state + 0.04 * pulse + 0.05 * alarm);

      ctx.clearRect(0, 0, W, H);
      ctx.save();
      ctx.globalCompositeOperation = "lighter";   // additives Glühen

      /* ---- 1) Weicher Außen-Halo --------------------------------- */
      {
        const haloR = u * (1.05 + 0.06 * breath + 0.10 * pulse + 0.12 * this.threat);
        const g = ctx.createRadialGradient(cx, cy, coreR * 0.2, cx, cy, haloR);
        const ha = 0.16 + 0.05 * breath + 0.10 * this.state + 0.08 * pulse + 0.10 * alarm;
        g.addColorStop(0.0, rgba(c, ha));
        g.addColorStop(0.45, rgba(c, ha * 0.35));
        g.addColorStop(1.0, rgba(c, 0));
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(cx, cy, haloR, 0, 6.2831853); ctx.fill();
      }

      /* ---- 2) Neuronales Partikelfeld ---------------------------- */
      {
        const p = this.particles;
        // dünne Verbindungslinien zu nahen Nachbarn (sparsam -> kein O(n^2)-Jank:
        // wir verbinden nur mit dem unmittelbaren Listen-Nachbarn).
        ctx.lineWidth = Math.max(0.5, u * 0.004);
        for (let i = 0; i < p.length; i++) {
          const a = p[i], b = p[(i + 1) % p.length];
          const ax = cx + Math.cos(a.ang) * a.rad * u;
          const ay = cy + Math.sin(a.ang) * a.rad * u;
          const bx = cx + Math.cos(b.ang) * b.rad * u;
          const by = cy + Math.sin(b.ang) * b.rad * u;
          const dx = ax - bx, dy = ay - by;
          const d2 = dx * dx + dy * dy;
          const maxD = u * 0.30;
          if (d2 < maxD * maxD) {
            const la = (1 - Math.sqrt(d2) / maxD) * (0.10 + 0.12 * this.state);
            ctx.strokeStyle = rgba(c, la);
            ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(bx, by); ctx.stroke();
          }
        }
        // die Knoten selbst (Twinkle).
        for (let i = 0; i < p.length; i++) {
          const a = p[i];
          const ax = cx + Math.cos(a.ang) * a.rad * u;
          const ay = cy + Math.sin(a.ang) * a.rad * u;
          const tw = 0.5 + 0.5 * Math.sin(a.tw);
          const pa = (0.25 + 0.5 * tw) * (0.6 + 0.4 * this.state);
          const ps = a.size * (0.6 + 0.5 * tw) * (u / 120);
          ctx.fillStyle = rgba(toward(c, WHITE, 0.3 * tw), pa);
          ctx.beginPath(); ctx.arc(ax, ay, ps, 0, 6.2831853); ctx.fill();
        }
      }

      /* ---- 3) Segmentierte HUD-Ringe (Reaktor-Spulen) ------------ */
      // Zwei gegenläufige Hauptringe + je nach Energie hellere Segmente.
      this._coilRing(ctx, cx, cy, u * 0.62, this.spin,          10, c, 0.55 + 0.25 * pulse, u * 0.05);
      this._coilRing(ctx, cx, cy, u * 0.50, -this.spin * 1.35,   8, c, 0.42 + 0.20 * pulse, u * 0.035);
      this._coilRing(ctx, cx, cy, u * 0.78,  this.spin * 0.55,  16, c, 0.28 + 0.15 * pulse, u * 0.025);

      /* ---- 4) Dünne Tick-/Skalen-Ringe (HUD-Detail) -------------- */
      {
        ctx.lineWidth = Math.max(0.5, u * 0.006);
        ctx.strokeStyle = rgba(c, 0.18 + 0.10 * this.state);
        ctx.beginPath(); ctx.arc(cx, cy, u * 0.86, 0, 6.2831853); ctx.stroke();
        ctx.strokeStyle = rgba(c, 0.12 + 0.08 * pulse);
        ctx.beginPath(); ctx.arc(cx, cy, u * 0.40, 0, 6.2831853); ctx.stroke();
        // kurze radiale Ticks am Außenring.
        const ticks = 48;
        ctx.lineWidth = Math.max(0.5, u * 0.004);
        for (let i = 0; i < ticks; i++) {
          const ang = (i / ticks) * Math.PI * 2 + this.spin * 0.2;
          const r0 = u * 0.84, r1 = u * (0.88 + (i % 4 === 0 ? 0.03 : 0));
          ctx.strokeStyle = rgba(c, i % 4 === 0 ? 0.28 : 0.12);
          ctx.beginPath();
          ctx.moveTo(cx + Math.cos(ang) * r0, cy + Math.sin(ang) * r0);
          ctx.lineTo(cx + Math.cos(ang) * r1, cy + Math.sin(ang) * r1);
          ctx.stroke();
        }
      }

      /* ---- 5) Plasma-Kern mit weiß-heißem Zentrum ---------------- */
      {
        // äußere Kern-Aura
        const g1 = ctx.createRadialGradient(cx, cy, 0, cx, cy, coreR * 1.5);
        g1.addColorStop(0.0, rgba(hot, 0.9));
        g1.addColorStop(0.35, rgba(c, 0.7));
        g1.addColorStop(1.0, rgba(c, 0));
        ctx.fillStyle = g1;
        ctx.beginPath(); ctx.arc(cx, cy, coreR * 1.5, 0, 6.2831853); ctx.fill();

        // heißer, dichter Kern
        const g2 = ctx.createRadialGradient(cx, cy, 0, cx, cy, coreR);
        g2.addColorStop(0.0, rgba(WHITE, 0.95));
        g2.addColorStop(0.5, rgba(hot, 0.85));
        g2.addColorStop(1.0, rgba(c, 0));
        ctx.fillStyle = g2;
        ctx.beginPath(); ctx.arc(cx, cy, coreR, 0, 6.2831853); ctx.fill();

        // winziger gleißender Kernpunkt
        ctx.fillStyle = rgba(WHITE, 0.7 + 0.2 * pulse);
        ctx.beginPath(); ctx.arc(cx, cy, coreR * (0.22 + 0.05 * pulse), 0, 6.2831853); ctx.fill();
      }

      /* ---- 6) Audio-artige Ripple-Wellen ------------------------- */
      {
        const rp = this.ripples;
        ctx.lineWidth = Math.max(0.8, u * 0.01);
        for (let i = 0; i < rp.length; i++) {
          ctx.strokeStyle = rgba(toward(c, WHITE, 0.2), rp[i].a);
          ctx.beginPath(); ctx.arc(cx, cy, rp[i].r * u, 0, 6.2831853); ctx.stroke();
        }
      }

      ctx.restore();
    },

    // Ein segmentierter, leuchtender Reaktor-Ring (gegen-/mitläufig rotierend).
    // breite = Linienstärke in px.
    _coilRing(ctx, cx, cy, r, rot, segs, col, alpha, width) {
      const gapFrac = 0.22;                    // Lücken-Anteil je Segment
      const step = (Math.PI * 2) / segs;
      ctx.lineWidth = Math.max(1, width);
      ctx.lineCap = "round";
      ctx.strokeStyle = rgba(col, clamp(alpha, 0, 1));
      for (let i = 0; i < segs; i++) {
        const a0 = rot + i * step + gapFrac * 0.5 * step;
        const a1 = rot + (i + 1) * step - gapFrac * 0.5 * step;
        ctx.beginPath();
        ctx.arc(cx, cy, r, a0, a1);
        ctx.stroke();
      }
    },

    /* ---- Resize (DPR moderat geclamped für scharfe, günstige Kanten) -- */
    _resize() {
      if (!this.canvas || this.mode !== "canvas2d") return;
      const w = this.canvas.clientWidth | 0;
      const h = this.canvas.clientHeight | 0;
      if (w === 0 || h === 0) return;
      // Canvas 2D ist günstig -> bis 2x DPR für scharfe Ringe/Glow.
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      const bw = Math.max(1, Math.round(w * dpr));
      const bh = Math.max(1, Math.round(h * dpr));
      if (this.canvas.width !== bw)  this.canvas.width  = bw;
      if (this.canvas.height !== bh) this.canvas.height = bh;

      // In CSS-Pixeln zeichnen (Transform übernimmt DPR-Skalierung).
      if (this.ctx) this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      this.W = w; this.H = h;
      this.cx = w / 2; this.cy = h / 2;
      // "unit" = halbe Kantenlänge des Kerns; alles skaliert relativ dazu.
      this.unit = Math.min(w, h) * 0.42;
    },

    /* ---- Overlay: State-Label + Aktivitätswert --------------------- */
    _overlay() {
      // Label: aktueller Betriebszustand des Kerns.
      const lbl = document.querySelector(".brain-overlay-label");
      if (lbl) {
        let txt;
        const age = this._now() - this.lastEventTs;
        if (this.threat > 0.25) {
          txt = "BEDROHUNG";
          if (this.lastEvent && age < 6000 && this.lastEvent.src)
            txt += " · " + this.lastEvent.src.slice(0, 20);
        } else if (this.voiceState === "listening") {
          txt = "HÖRE ZU";
        } else if (this.voiceState === "speaking") {
          txt = "SPRECHE";
        } else if (this.thinkingOn || this.state > 0.4) {
          txt = "DENKE";
        } else if (this.lastEvent && age < 6000) {
          txt = this.lastEvent.cat + (this.lastEvent.src ? " · " + this.lastEvent.src.slice(0, 20) : "");
        } else {
          txt = "BEREIT";
        }
        lbl.textContent = txt;
      }

      // Aktivitätswert (0..100) für den Energiekern; #brain-total = Skala 100.
      const act = Math.round(clamp(this.state * 0.6 + this.pulse * 0.3 + this.threat * 0.4, 0, 1) * 100);
      const at = document.getElementById("brain-active"); if (at) at.textContent = act;
      const tt = document.getElementById("brain-total");  if (tt) tt.textContent = 100;
    },
  };

  window.AegisBrain = Brain;
  document.addEventListener("DOMContentLoaded", () => {
    if (window.__aegisBrainGLActive) return;   // WebGL-Core (brain-gl.js) hat uebernommen
    const c = document.getElementById("brain-canvas");
    if (c) { try { Brain.init(c); } catch (e) { /* still — nie crashen */ } }
  });
})();
