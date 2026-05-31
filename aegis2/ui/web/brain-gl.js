/* ============================================================
   AEGIS — Cognition-Core (WebGL2 / Three.js, 2026)
   ------------------------------------------------------------
   Premium-Variante des "Brain": Fresnel-Glow-Kern + heller
   Innenkern + Arc-Reactor-Ringe + additives Partikel-Swirl-Feld,
   HDR-artiges Additiv-Compositing. Zustands-reaktiv (idle / denke /
   höre / spreche / Bedrohung) — API 1:1 zu brain.js.

   SICHERHEIT/ROBUSTHEIT: Übernimmt NUR, wenn echtes GPU-WebGL da ist.
   Bei Software-Rendering (SwiftShader/llvmpipe) oder ohne Three bleibt
   die Canvas2D-Version (brain.js) aktiv → nie ein schwarzer Kern.
   ============================================================ */
"use strict";
(function () {
  if (!window.THREE) return;                 // kein Three -> Canvas2D-Fallback
  const THREE = window.THREE;

  function webglUsable() {
    try {
      const c = document.createElement("canvas");
      const gl = c.getContext("webgl2") || c.getContext("webgl");
      if (!gl) return false;
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      const r = ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "") : "";
      if (/swiftshader|software|llvmpipe|microsoft basic render/i.test(r)) return false;
      return true;
    } catch (e) { return false; }
  }

  const lerp = (a, b, t) => a + (b - a) * t;
  const C_IDLE   = new THREE.Color(0.16, 0.60, 0.96);
  const C_THINK  = new THREE.Color(0.32, 0.80, 1.00);
  const C_VOICE  = new THREE.Color(0.46, 0.56, 1.00);
  const C_WARN   = new THREE.Color(1.00, 0.66, 0.18);
  const C_THREAT = new THREE.Color(1.00, 0.22, 0.27);

  const GL = {
    ok: false, _raf: 0,
    state: 0, stateTarget: 0, pulse: 0, threat: 0, threatTarget: 0,
    thinkingOn: false, voiceState: "", _voiceTs: 0,
    col: C_IDLE.clone(),

    init(canvas) {
      if (!canvas || !webglUsable()) return false;
      try { this._build(canvas); } catch (e) { try { console.warn("brain-gl build failed", e); } catch (_) {} return false; }
      this.ok = true;
      this._t0 = performance.now();
      this._last = this._t0;
      this._loop();
      return true;
    },

    _build(canvas) {
      const stage = canvas.parentElement || canvas;
      const W = stage.clientWidth || 460, H = stage.clientHeight || 460;
      this.canvas = canvas; this.stage = stage;

      const r = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: true,
                                          powerPreference: "high-performance" });
      r.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
      r.setSize(W, H, false);
      r.setClearColor(0x000000, 0);
      this.renderer = r;

      const scene = new THREE.Scene(); this.scene = scene;
      const cam = new THREE.PerspectiveCamera(42, W / H, 0.1, 100);
      cam.position.set(0, 0, 7.4); this.camera = cam;

      // ---- Glow-Kern (Fresnel) ----
      const cu = { uTime: { value: 0 }, uColor: { value: this.col.clone() },
                   uIntensity: { value: 1.0 }, uFres: { value: 2.5 } };
      this.cu = cu;
      const coreMat = new THREE.ShaderMaterial({
        uniforms: cu, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
        vertexShader: [
          "uniform float uTime; varying vec3 vN; varying vec3 vV;",
          "float h(vec3 p){return fract(sin(dot(p,vec3(12.9898,78.233,37.719)))*43758.5453);}",
          "float nz(vec3 p){vec3 i=floor(p),f=fract(p);f=f*f*(3.0-2.0*f);",
          " return mix(mix(mix(h(i),h(i+vec3(1,0,0)),f.x),mix(h(i+vec3(0,1,0)),h(i+vec3(1,1,0)),f.x),f.y),",
          " mix(mix(h(i+vec3(0,0,1)),h(i+vec3(1,0,1)),f.x),mix(h(i+vec3(0,1,1)),h(i+vec3(1,1,1)),f.x),f.y),f.z);}",
          "void main(){vec3 p=position;float d=nz(normalize(p)*2.2+uTime*0.25)*0.13;p+=normal*d;",
          " vN=normalize(normalMatrix*normal);vec4 mv=modelViewMatrix*vec4(p,1.0);vV=normalize(-mv.xyz);",
          " gl_Position=projectionMatrix*mv;}"
        ].join("\n"),
        fragmentShader: [
          "uniform vec3 uColor;uniform float uIntensity;uniform float uFres;varying vec3 vN;varying vec3 vV;",
          "void main(){float f=pow(1.0-max(dot(vN,vV),0.0),uFres);float c=pow(max(dot(vN,vV),0.0),1.5)*0.45;",
          " float a=(f*1.3+c)*uIntensity;gl_FragColor=vec4(uColor*(0.55+f*1.7)*uIntensity,a);}"
        ].join("\n"),
      });
      this.core = new THREE.Mesh(new THREE.IcosahedronGeometry(1.5, 5), coreMat);
      scene.add(this.core);

      // ---- heller Innenkern (fast weiss) ----
      const innerMat = new THREE.ShaderMaterial({
        uniforms: cu, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
        vertexShader: "varying vec3 vN;varying vec3 vV;void main(){vN=normalize(normalMatrix*normal);" +
          "vec4 mv=modelViewMatrix*vec4(position,1.0);vV=normalize(-mv.xyz);gl_Position=projectionMatrix*mv;}",
        fragmentShader: "uniform vec3 uColor;uniform float uIntensity;varying vec3 vN;varying vec3 vV;" +
          "void main(){float c=pow(max(dot(vN,vV),0.0),2.0);vec3 col=mix(uColor,vec3(1.0),0.72);" +
          "gl_FragColor=vec4(col*c*1.5*uIntensity,c*uIntensity);}",
      });
      this.inner = new THREE.Mesh(new THREE.IcosahedronGeometry(0.85, 3), innerMat);
      scene.add(this.inner);

      // ---- Arc-Reactor-Ringe ----
      this.rings = [];
      for (let i = 0; i < 3; i++) {
        const m = new THREE.MeshBasicMaterial({ color: this.col.clone(), transparent: true,
          blending: THREE.AdditiveBlending, depthWrite: false, opacity: 0.5 - i * 0.1 });
        const ring = new THREE.Mesh(new THREE.TorusGeometry(2.2 + i * 0.55, 0.012 + i * 0.004, 8, 170), m);
        ring.rotation.x = Math.PI / 2 + i * 0.3; ring.rotation.y = i * 0.4;
        ring._spin = (i % 2 === 0 ? 1 : -1) * (0.12 + i * 0.05);
        scene.add(ring); this.rings.push(ring);
      }

      // ---- Partikel-Swirl-Feld (additiv) ----
      const N = 4200;
      const pos = new Float32Array(N * 3), seed = new Float32Array(N);
      for (let i = 0; i < N; i++) {
        const u = Math.random(), v = Math.random();
        const th = 2 * Math.PI * u, ph = Math.acos(2 * v - 1), rr = 2.0 + Math.random() * 2.7;
        pos[i * 3] = rr * Math.sin(ph) * Math.cos(th);
        pos[i * 3 + 1] = rr * Math.sin(ph) * Math.sin(th);
        pos[i * 3 + 2] = rr * Math.cos(ph);
        seed[i] = Math.random();
      }
      const pg = new THREE.BufferGeometry();
      pg.setAttribute("position", new THREE.BufferAttribute(pos, 3));
      pg.setAttribute("aSeed", new THREE.BufferAttribute(seed, 1));
      const pu = { uTime: { value: 0 }, uColor: { value: this.col.clone() },
                   uSize: { value: H / 12 }, uSpeed: { value: 1.0 }, uIntensity: { value: 1.0 } };
      this.pu = pu;
      const pMat = new THREE.ShaderMaterial({
        uniforms: pu, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
        vertexShader: [
          "uniform float uTime;uniform float uSize;uniform float uSpeed;attribute float aSeed;varying float vA;",
          "void main(){vec3 p=position;float a=uTime*uSpeed*(0.15+aSeed*0.25);float s=sin(a+aSeed*6.28),c=cos(a+aSeed*6.28);",
          " p.xz=mat2(c,-s,s,c)*p.xz;p+=normalize(p)*sin(uTime*0.6+aSeed*9.0)*0.12;",
          " vec4 mv=modelViewMatrix*vec4(p,1.0);gl_PointSize=uSize*(0.4+aSeed*0.8)/max(-mv.z,0.1);vA=0.4+aSeed*0.6;",
          " gl_Position=projectionMatrix*mv;}"
        ].join("\n"),
        fragmentShader: "uniform vec3 uColor;uniform float uIntensity;varying float vA;" +
          "void main(){vec2 d=gl_PointCoord-0.5;float r=length(d);" +
          "float al=pow(1.0-smoothstep(0.0,0.5,r),1.6)*vA*uIntensity;gl_FragColor=vec4(uColor*1.6,al);}",
      });
      this.points = new THREE.Points(pg, pMat); scene.add(this.points);

      this._onResize = () => this._resize();
      window.addEventListener("resize", this._onResize);
    },

    _resize() {
      if (!this.renderer) return;
      const W = this.stage.clientWidth || 460, H = this.stage.clientHeight || 460;
      this.renderer.setSize(W, H, false);
      this.camera.aspect = W / H; this.camera.updateProjectionMatrix();
      if (this.pu) this.pu.uSize.value = H / 12;
    },

    _loop() {
      this._raf = requestAnimationFrame(() => this._loop());
      const now = performance.now();
      let dt = (now - this._last) / 1000; this._last = now;
      if (dt > 0.05) dt = 0.05;
      const t = (now - this._t0) / 1000;
      // Tab unsichtbar -> nicht rendern (Strom sparen)
      if (document.hidden || !this.stage || this.stage.clientWidth === 0) return;

      this.state = lerp(this.state, this.stateTarget, 1 - Math.pow(0.0001, dt));
      this.threat = lerp(this.threat, this.threatTarget, 1 - Math.pow(0.002, dt));
      this.pulse *= Math.pow(0.12, dt);
      this.stateTarget *= Math.pow(0.6, dt);
      this.threatTarget *= Math.pow(0.7, dt);

      let target = this.threat > 0.5 ? C_THREAT
                 : (this.threat > 0.2 ? C_WARN
                 : ((this.voiceState === "listening" || this.voiceState === "speaking") ? C_VOICE
                 : ((this.thinkingOn || this.state > 0.4) ? C_THINK : C_IDLE)));
      this.col.lerp(target, 1 - Math.pow(0.01, dt));

      const energy = Math.min(1.4, this.state * 0.7 + this.pulse * 0.8 + this.threat * 0.5);
      const speed = 0.6 + energy * 1.6 + this.threat * 1.0;

      this.cu.uTime.value = t; this.cu.uColor.value.copy(this.col);
      this.cu.uIntensity.value = 0.85 + energy * 0.6; this.cu.uFres.value = 2.6 - this.state * 0.8;
      this.pu.uTime.value = t; this.pu.uColor.value.copy(this.col);
      this.pu.uSpeed.value = speed; this.pu.uIntensity.value = 0.7 + energy * 0.7;

      const k = dt * (0.4 + energy * 1.2);
      this.core.rotation.y += k * 0.3; this.core.rotation.x += k * 0.12;
      this.inner.rotation.y -= k * 0.5;
      this.inner.scale.setScalar(1.0 + Math.sin(t * 2.0) * 0.02 + this.pulse * 0.06);
      this.points.rotation.y += dt * (0.05 + energy * 0.15);
      for (const ring of this.rings) {
        ring.rotation.z += ring._spin * dt * (0.6 + energy);
        ring.material.color.copy(this.col);
        ring.material.opacity = 0.32 + energy * 0.3;
      }

      try { this.renderer.render(this.scene, this.camera); } catch (e) {}
      this._overlay();
    },

    _overlay() {
      const lbl = document.querySelector(".brain-overlay-label");
      if (!lbl) return;
      let txt = "BEREIT";
      if (this.threat > 0.5) txt = "ALARM";
      else if (this.thinkingOn || this.state > 0.45) txt = "DENKE";
      else if (this.voiceState === "listening") txt = "HÖRE";
      else if (this.voiceState === "speaking") txt = "SPRECHE";
      if (lbl.textContent !== txt) lbl.textContent = txt;
    },

    /* ---- Public API (1:1 zu brain.js) ---- */
    activateForEvent(ev) {
      if (!ev) return;
      const cat = (ev.category || "SYSTEM").toString().toUpperCase();
      const sev = (ev.severity || "INFO").toString().toUpperCase();
      const power = sev === "CRITICAL" ? 1.0 : sev === "THREAT" ? 0.95
                  : sev === "QUARANTINE" ? 0.8 : sev === "WARN" ? 0.65 : 0.45;
      this.stateTarget = Math.max(this.stateTarget, Math.min(1, power));
      this.pulse = Math.min(1.4, this.pulse + power * 0.9);
      const danger = (sev === "CRITICAL" || sev === "THREAT" || cat === "TAMPER");
      if (danger) this.threatTarget = 1.0;
      else if (sev === "WARN") this.threatTarget = Math.max(this.threatTarget, 0.45);
      if (cat === "VOICE") {
        const src = (ev.source || "").toString().toLowerCase();
        if (src === "listening" || src === "speaking" || src === "thinking") {
          this.voiceState = src; this._voiceTs = performance.now();
        }
      }
    },
    thinking(on) { this.thinkingOn = !!on; if (on) this.stateTarget = Math.max(this.stateTarget, 0.85); },
    setMood() {},
    sizeFor() { try { this._resize(); } catch (e) {} },
  };

  // Beim Laden: WebGL nutzbar -> uebernehmen; sonst Canvas2D (brain.js) lassen.
  window.__aegisBrainGLActive = false;
  document.addEventListener("DOMContentLoaded", function () {
    const c = document.getElementById("brain-canvas");
    if (!c) return;
    if (GL.init(c)) {
      window.__aegisBrainGLActive = true;
      window.AegisBrain = GL;
      try { console.log("AEGIS cognition core: WebGL active"); } catch (e) {}
    }
  });
})();
