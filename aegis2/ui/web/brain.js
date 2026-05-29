/* ============================================================
   AEGIS Cognition Brain — Wireframe-Sphere mit Activity-Mapping
   ------------------------------------------------------------
   Pure Canvas2D + manuelle 3D-Projektion. Kein Three.js (CDN-
   Risiko in privilegierter WebView).

   Vertices = Cognition-Knoten. Aufleuchten NUR wenn ein echtes
   Event seine Source/Kategorie auf den Knoten mappt. Edges
   pulsieren wenn zwei verbundene Vertices kurz hintereinander
   aktiv waren (= "thought transfer").

   Performance:
     - 24 longitude × 16 latitude = ~360 vertices, ~720 edges
     - 30 fps fixed step, pause wenn nicht sichtbar
     - GPU-freundlich: nur Lines + Circles, kein Filter/Blur

   Public API:
     window.AegisBrain = {
       init(canvasEl, overlayEl),
       activateForEvent(ev),     // call from app.js onEvent
       thinking(on),             // shows "cognition busy" pulse
       sizeFor(view),            // resize when tab shown
     }
   ============================================================ */
"use strict";

(function () {

  const LON_STEPS = 24;      // meridians
  const LAT_STEPS = 16;      // parallels (excluding poles)
  const RADIUS = 1.0;

  const COL_BG_WIRE = "rgba(120, 160, 200, 0.18)";   // dim sphere lines
  const COL_BG_DOT  = "rgba(180, 200, 230, 0.35)";   // dim vertex dots

  const COL_ACT     = [143, 209, 255];               // active blue
  const COL_THREAT  = [249, 115, 115];
  const COL_WARN    = [250, 204, 21];
  const COL_QUAR    = [181, 141, 255];
  const COL_HUB     = [255, 255, 255];

  const DEFAULT_DECAY = 0.96;     // per-frame activity multiplier
  const HUB_DECAY     = 0.985;
  const EDGE_DECAY    = 0.92;

  // Source-to-vertex deterministic mapping. Stable across sessions.
  function djb2(str) {
    let h = 5381;
    for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) | 0;
    return Math.abs(h);
  }

  // Category → preferred latitude bias (visual grouping)
  const CAT_LAT_BIAS = {
    SYSTEM:     0.0,   // equator
    NETWORK:    0.45,  // mid-upper
    DNS:        0.35,
    PROCESS:    0.0,
    FILE:      -0.40,  // mid-lower
    URL:        0.55,
    QUARANTINE: -0.55,
    VOICE:      0.75,  // very top
    TAMPER:     0.85,  // pole
  };

  /* ---------------- Sphere generation ---------------- */
  function buildSphere() {
    const vertices = [];   // {x,y,z, isHub, cat, source}
    const edges = [];      // {a,b}
    const ringIdx = [];    // per-latitude row: list of vertex indices

    // poles
    const top = vertices.length;
    vertices.push({ x: 0, y: -RADIUS, z: 0, isHub: true });
    ringIdx.push([top]);

    for (let lat = 1; lat <= LAT_STEPS; lat++) {
      const phi = (lat / (LAT_STEPS + 1)) * Math.PI;   // 0..PI
      const y = -Math.cos(phi) * RADIUS;
      const r = Math.sin(phi) * RADIUS;
      const row = [];
      for (let lon = 0; lon < LON_STEPS; lon++) {
        const theta = (lon / LON_STEPS) * Math.PI * 2;
        const x = Math.cos(theta) * r;
        const z = Math.sin(theta) * r;
        row.push(vertices.length);
        vertices.push({ x, y, z, isHub: false });
      }
      ringIdx.push(row);
    }
    const bottom = vertices.length;
    vertices.push({ x: 0, y: RADIUS, z: 0, isHub: true });
    ringIdx.push([bottom]);

    // edges: longitude lines (lat rings)
    for (let r = 1; r <= LAT_STEPS; r++) {
      const row = ringIdx[r];
      for (let i = 0; i < row.length; i++) {
        edges.push({ a: row[i], b: row[(i + 1) % row.length] });
      }
    }
    // meridians: connect ring-i[k] -> ring-(i+1)[k]
    for (let r = 0; r < ringIdx.length - 1; r++) {
      const A = ringIdx[r], B = ringIdx[r + 1];
      if (A.length === 1 && B.length > 1) {
        for (const v of B) edges.push({ a: A[0], b: v });
      } else if (A.length > 1 && B.length === 1) {
        for (const v of A) edges.push({ a: v, b: B[0] });
      } else {
        for (let k = 0; k < A.length; k++) edges.push({ a: A[k], b: B[k] });
      }
    }

    // pick hub vertices on the equator (mid-row)
    const equator = ringIdx[Math.floor(ringIdx.length / 2)];
    for (let i = 0; i < equator.length; i += Math.max(1, Math.floor(LON_STEPS / 6))) {
      vertices[equator[i]].isHub = true;
    }

    // adjacency for "thought transfer"
    const adj = vertices.map(() => []);
    edges.forEach((e, ei) => {
      adj[e.a].push({ ei, other: e.b });
      adj[e.b].push({ ei, other: e.a });
    });

    return { vertices, edges, ringIdx, adj };
  }

  /* ---------------- Brain controller ---------------- */
  const Brain = {
    canvas: null, ctx: null, overlay: null,
    geom: null,
    activity: null,        // Float32Array per vertex
    edgeActivity: null,
    yaw: 0, pitch: 0.18,
    userYaw: 0, userPitch: 0,
    dragging: false, lastMx: 0, lastMy: 0,
    autoRot: 0.0035,       // rad/frame
    visible: false,
    thinkingPulse: 0,      // 0..1, set by thinking(true)
    lastFrameTs: 0,
    activeCount: 0,

    init(canvas, overlay) {
      this.canvas = canvas;
      this.ctx = canvas.getContext("2d");
      this.overlay = overlay;
      this.geom = buildSphere();
      this.activity = new Float32Array(this.geom.vertices.length);
      this.edgeActivity = new Float32Array(this.geom.edges.length);
      this.lastVtxByCat = {};   // for chain-edge pulses

      // resize
      const ro = new ResizeObserver(() => this._resize());
      ro.observe(canvas);
      this._resize();

      // mouse
      canvas.addEventListener("mousedown", (e) => {
        this.dragging = true; this.lastMx = e.clientX; this.lastMy = e.clientY;
      });
      window.addEventListener("mouseup", () => { this.dragging = false; });
      canvas.addEventListener("mousemove", (e) => {
        if (!this.dragging) return;
        const dx = e.clientX - this.lastMx, dy = e.clientY - this.lastMy;
        this.lastMx = e.clientX; this.lastMy = e.clientY;
        this.userYaw += dx * 0.006;
        this.userPitch = Math.max(-1.1, Math.min(1.1, this.userPitch + dy * 0.005));
      });

      // intersection-observer style — only run when stage visible
      const io = new IntersectionObserver((entries) => {
        entries.forEach(en => { this.visible = en.isIntersecting; });
      }, { threshold: 0.05 });
      io.observe(canvas);

      // boot loop
      this.lastFrameTs = performance.now();
      const tick = (ts) => {
        const dt = Math.min(80, ts - this.lastFrameTs);
        this.lastFrameTs = ts;
        if (this.visible && !document.hidden) {
          this._step(dt);
          this._draw();
          this._updateOverlay();
        }
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    },

    // Public: light up vertices for a real event
    activateForEvent(ev) {
      if (!ev || !this.geom) return;
      const sev = ev.severity || "INFO";
      const cat = ev.category || "SYSTEM";
      const src = ev.source || cat;

      // Vertex index: source-hash mod numVertices, biased by category latitude
      const N = this.geom.vertices.length;
      const h = djb2(`${cat}::${src}`);
      // Determine ring by category bias
      const ringCount = this.geom.ringIdx.length;
      const biasLat = CAT_LAT_BIAS[cat] ?? 0.0;       // -1..+1
      const ringNorm = (biasLat + 1) / 2;             // 0..1
      const ringTarget = Math.round(ringNorm * (ringCount - 1));
      const ring = this.geom.ringIdx[ringTarget];
      const idx = ring[h % ring.length];

      // Strength by severity
      const power = sev === "CRITICAL" ? 1.0
                 : sev === "THREAT"    ? 0.9
                 : sev === "WARN"      ? 0.7
                 : sev === "QUARANTINE"? 0.85
                 : 0.45;

      this.activity[idx] = Math.min(1.0, this.activity[idx] + power);

      // "Thought transfer": if a previous vertex of same cat exists, pulse the edges between
      const prev = this.lastVtxByCat[cat];
      if (prev != null && prev !== idx) {
        this._pulsePath(prev, idx, 0.7);
      }
      this.lastVtxByCat[cat] = idx;
    },

    thinking(on) {
      this.thinkingPulse = on ? 1.0 : 0.0;
    },

    _pulsePath(fromIdx, toIdx, strength) {
      // simple BFS to find path, limited depth
      const visited = new Set([fromIdx]);
      const frontier = [{ at: fromIdx, path: [] }];
      const limit = 6;
      while (frontier.length) {
        const cur = frontier.shift();
        if (cur.path.length > limit) continue;
        if (cur.at === toIdx) {
          for (const ei of cur.path) {
            this.edgeActivity[ei] = Math.min(1.0, this.edgeActivity[ei] + strength);
          }
          return;
        }
        for (const nb of this.geom.adj[cur.at]) {
          if (visited.has(nb.other)) continue;
          visited.add(nb.other);
          frontier.push({ at: nb.other, path: [...cur.path, nb.ei] });
        }
      }
    },

    _step(dt) {
      // auto rotate (only if user hasn't dragged recently — we keep simple here)
      this.yaw += this.autoRot * (dt / 33);

      // decay activity
      const dec = Math.pow(DEFAULT_DECAY, dt / 33);
      const decHub = Math.pow(HUB_DECAY, dt / 33);
      const decEdge = Math.pow(EDGE_DECAY, dt / 33);
      let active = 0;
      for (let i = 0; i < this.activity.length; i++) {
        const isHub = this.geom.vertices[i].isHub;
        this.activity[i] *= (isHub ? decHub : dec);
        if (this.activity[i] < 0.005) this.activity[i] = 0;
        else if (this.activity[i] > 0.04) active++;
      }
      this.activeCount = active;
      for (let i = 0; i < this.edgeActivity.length; i++) {
        this.edgeActivity[i] *= decEdge;
        if (this.edgeActivity[i] < 0.01) this.edgeActivity[i] = 0;
      }

      if (this.thinkingPulse > 0) {
        // subtle global pulse — keeps every vertex 5% lit while thinking
        for (let i = 0; i < this.activity.length; i++) {
          this.activity[i] = Math.max(this.activity[i], 0.05 * this.thinkingPulse);
        }
        this.thinkingPulse *= 0.99;   // slow fade
      }
    },

    _project(x, y, z) {
      const yaw = this.yaw + this.userYaw;
      const pitch = this.pitch + this.userPitch;
      const cy = Math.cos(yaw), sy = Math.sin(yaw);
      const cp = Math.cos(pitch), sp = Math.sin(pitch);
      // rotate around Y
      const x1 = x * cy + z * sy;
      const z1 = -x * sy + z * cy;
      const y1 = y;
      // rotate around X
      const y2 = y1 * cp - z1 * sp;
      const z2 = y1 * sp + z1 * cp;
      // perspective
      const camZ = 2.4;
      const denom = Math.max(0.12, camZ - z2);
      const scale = 1.9 / denom;
      return { sx: x1 * scale, sy: y2 * scale, depth: z2, ps: scale };
    },

    _resize() {
      const w = this.canvas.clientWidth | 0;
      const h = this.canvas.clientHeight | 0;
      const dpr = window.devicePixelRatio || 1;
      this.canvas.width = Math.max(1, w * dpr);
      this.canvas.height = Math.max(1, h * dpr);
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    },

    _draw() {
      const ctx = this.ctx;
      const w = this.canvas.clientWidth;
      const h = this.canvas.clientHeight;
      const cx = w / 2, cy = h / 2;
      const px = Math.min(w, h) * 0.36;   // pixels per unit

      ctx.clearRect(0, 0, w, h);

      // project all vertices
      const verts = this.geom.vertices;
      const proj = new Array(verts.length);
      for (let i = 0; i < verts.length; i++) {
        const v = verts[i];
        const p = this._project(v.x, v.y, v.z);
        proj[i] = { sx: cx + p.sx * px, sy: cy + p.sy * px, depth: p.depth, ps: p.ps };
      }

      // edges back-to-front
      const order = new Array(this.geom.edges.length);
      for (let i = 0; i < this.geom.edges.length; i++) {
        const e = this.geom.edges[i];
        order[i] = { i, avg: (proj[e.a].depth + proj[e.b].depth) * 0.5 };
      }
      order.sort((A, B) => A.avg - B.avg);

      for (const o of order) {
        const e = this.geom.edges[o.i];
        const pa = proj[e.a], pb = proj[e.b];
        const ea = this.edgeActivity[o.i];
        const depthFog = Math.max(0.0, Math.min(1.0, (o.avg + 1.0) / 2.0));

        if (ea > 0.02) {
          ctx.strokeStyle = `rgba(${COL_ACT[0]},${COL_ACT[1]},${COL_ACT[2]},${0.35 + ea * 0.65})`;
          ctx.lineWidth = 1.6 + ea * 2.4;
        } else {
          // dim wireframe — thicker, more present
          const alpha = 0.14 + depthFog * 0.22;
          ctx.strokeStyle = `rgba(150, 195, 235, ${alpha})`;
          ctx.lineWidth = 1.25;
        }
        ctx.beginPath();
        ctx.moveTo(pa.sx, pa.sy);
        ctx.lineTo(pb.sx, pb.sy);
        ctx.stroke();
      }

      // vertices — dots, only "glow" the active ones
      const vorder = new Array(verts.length);
      for (let i = 0; i < verts.length; i++) vorder[i] = i;
      vorder.sort((A, B) => proj[A].depth - proj[B].depth);

      for (const i of vorder) {
        const p = proj[i];
        const v = verts[i];
        const a = this.activity[i];
        const depthFog = Math.max(0.0, Math.min(1.0, (p.depth + 1.0) / 2.0));

        // baseline dot — slightly bigger to read against thicker lines
        const baseR = (v.isHub ? 2.6 : 1.6) * p.ps;
        ctx.fillStyle = v.isHub
          ? `rgba(195, 230, 255, ${0.45 + depthFog * 0.40})`
          : `rgba(180, 210, 235, ${0.28 + depthFog * 0.30})`;
        ctx.beginPath();
        ctx.arc(p.sx, p.sy, baseR, 0, Math.PI * 2);
        ctx.fill();

        if (a > 0.02) {
          // halo
          const haloR = baseR * (3 + a * 6);
          const grad = ctx.createRadialGradient(p.sx, p.sy, baseR * 0.4, p.sx, p.sy, haloR);
          grad.addColorStop(0, `rgba(${COL_ACT[0]},${COL_ACT[1]},${COL_ACT[2]},${0.55 * a})`);
          grad.addColorStop(0.5, `rgba(${COL_ACT[0]},${COL_ACT[1]},${COL_ACT[2]},${0.18 * a})`);
          grad.addColorStop(1.0, `rgba(${COL_ACT[0]},${COL_ACT[1]},${COL_ACT[2]},0)`);
          ctx.fillStyle = grad;
          ctx.beginPath();
          ctx.arc(p.sx, p.sy, haloR, 0, Math.PI * 2);
          ctx.fill();

          // bright core
          ctx.fillStyle = `rgba(220, 240, 255, ${0.6 + 0.4 * a})`;
          ctx.beginPath();
          ctx.arc(p.sx, p.sy, baseR * (1.0 + a * 1.4), 0, Math.PI * 2);
          ctx.fill();
        }
      }
    },

    _updateOverlay() {
      const at = document.getElementById("brain-active");
      const tt = document.getElementById("brain-total");
      if (at) at.textContent = this.activeCount;
      if (tt) tt.textContent = this.geom.vertices.length;
    },
  };

  window.AegisBrain = Brain;

  // Auto-init when DOM ready
  document.addEventListener("DOMContentLoaded", () => {
    const canvas = document.getElementById("brain-canvas");
    const overlay = document.getElementById("brain-overlay");
    if (canvas) Brain.init(canvas, overlay);
  });
})();
