/* ============================================================
   AEGIS V2 — Update-Approval-Dialog Logic (Phase 7)
   ------------------------------------------------------------
   - Hört auf service-pushed Events vom GitHub-Updater
   - Zeigt Modal mit Sigstore-Verify-Status, Version, Changelog
   - Buttons:   [Install Now] [Later] [Skip]
   - Per IPC ueber `aegis.cmd()`:
        update.install     -> orchestrator triggert auto_update.py
        update.skip        -> markiert Version als skipped in DB
        update.remind      -> verschiebt 24h
   ============================================================ */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  // Cached current update meta (set when modal opens, used by button clicks)
  let currentMeta = null;

  // ----- DOM refs -----
  const modal       = $("update-modal");
  const titleEl     = $("update-title");
  const subtitleEl  = $("update-subtitle");
  const iconEl      = $("update-icon");
  const sigPanel    = $("sig-panel");
  const sigIcon     = $("sig-icon");
  const sigHeadline = $("sig-headline");
  const sigDetail   = $("sig-detail");
  const versionEl   = $("update-version");
  const sizeEl      = $("update-size");
  const shaEl       = $("update-sha");
  const changelogEl = $("update-changelog");
  const installBtn  = $("update-install");
  const laterBtn    = $("update-later");
  const skipBtn     = $("update-skip");
  const closeBtn    = $("update-close");
  const progressEl  = $("update-progress");
  const progressTxt = $("update-progress-text");
  const progressSub = $("update-progress-detail");

  // ----- Helpers -----
  function bytes(n) {
    if (typeof n !== "number") return "—";
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(2) + " MB";
  }

  function shortSha(s) {
    if (!s || typeof s !== "string") return "—";
    return s.length > 16 ? s.substring(0, 12) + "…" : s;
  }

  function setSignatureState(meta) {
    const verified = meta.signature_verified;
    const reason   = meta.signature_reason || "no info";
    if (verified === true) {
      sigPanel.classList.remove("is-warn", "is-bad");
      sigIcon.textContent = "✓";
      sigHeadline.textContent = "Sigstore signature verified";
      sigDetail.textContent =
        "Cert chain matches " + (meta.expected_repo || "release workflow") +
        ", Rekor-logged.";
    } else if (verified === false) {
      sigPanel.classList.remove("is-bad");
      sigPanel.classList.add("is-warn");
      sigIcon.textContent = "!";
      sigHeadline.textContent = "Signature verification FAILED";
      sigDetail.textContent = reason;
      installBtn.disabled = true;
      installBtn.title    = "Refusing to install unverified release";
    } else {
      sigPanel.classList.add("is-warn");
      sigIcon.textContent = "?";
      sigHeadline.textContent = "No signature provided";
      sigDetail.textContent = "Release lacks .sig/.crt assets. Refusing.";
      installBtn.disabled = true;
      installBtn.title    = "Refusing to install unsigned release";
    }
  }

  function fmtChangelog(notes) {
    if (!notes || typeof notes !== "string") return "(keine Release-Notes vorhanden)";
    // Strip the verification snippet & SHA noise that AEGIS workflows emit —
    // those are technical, not user-facing
    return notes
      .replace(/```[\s\S]*?```/g, "")    // code blocks
      .replace(/^#+\s+/gm, "")           // markdown headers
      .replace(/\n{3,}/g, "\n\n")        // collapse blank runs
      .trim()
      .substring(0, 1200);
  }

  // ----- Show / hide -----
  function open(meta) {
    currentMeta = meta || {};
    titleEl.textContent = "Update verfügbar";
    subtitleEl.textContent =
      (meta.current ? "v" + meta.current : "—") + "  →  " + (meta.version || "—");

    versionEl.textContent   = meta.version || "—";
    sizeEl.textContent      = bytes(meta.size_bytes);
    shaEl.textContent       = shortSha(meta.sha256);
    shaEl.title             = meta.sha256 || "";
    changelogEl.textContent = fmtChangelog(meta.release_notes);

    installBtn.disabled = false;
    installBtn.title    = "";
    progressEl.hidden   = true;
    setSignatureState(meta);

    modal.hidden = false;
    modal.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
    installBtn.focus();
  }

  function close() {
    modal.hidden = true;
    modal.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
    currentMeta = null;
    progressEl.hidden = true;
  }

  // ----- Backend calls -----
  function sendCmd(name, args) {
    if (!window.aegis || typeof window.aegis.cmd !== "function") {
      console.warn("aegis bridge not ready");
      return null;
    }
    try {
      return window.aegis.cmd(JSON.stringify({ name: name, args: args || {} }));
    } catch (e) {
      console.error("cmd failed", e);
      return null;
    }
  }

  function startProgress(text, detail) {
    progressTxt.textContent = text || "Installation läuft…";
    progressSub.textContent = detail || "";
    progressEl.hidden = false;
    installBtn.disabled = true;
    laterBtn.disabled   = true;
    skipBtn.disabled    = true;
    closeBtn.disabled   = true;
  }

  // ----- Button handlers -----
  installBtn.addEventListener("click", () => {
    if (!currentMeta) return;
    // Hard gate: only proceed if signature is verified
    if (currentMeta.signature_verified !== true) {
      progressTxt.textContent = "Signature not verified — refusing install";
      progressEl.hidden = false;
      return;
    }
    startProgress("Installation läuft…", "Service wird gestoppt");
    sendCmd("update.install", { version: currentMeta.version });
  });

  laterBtn.addEventListener("click", () => {
    if (currentMeta) sendCmd("update.remind", { version: currentMeta.version });
    close();
  });

  skipBtn.addEventListener("click", () => {
    if (currentMeta) sendCmd("update.skip", { version: currentMeta.version });
    close();
  });

  closeBtn.addEventListener("click", close);

  // Esc to dismiss (treated as Later, not Skip)
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !modal.hidden) {
      laterBtn.click();
    }
  });

  // ----- Listen for service-pushed update events -----
  function tryWireBridge() {
    if (!window.aegis || !window.aegis.eventReceived) {
      setTimeout(tryWireBridge, 200);
      return;
    }
    window.aegis.eventReceived.connect((json) => {
      let ev;
      try { ev = JSON.parse(json); } catch (_) { return; }

      // GitHub-Updater emits with category=SYSTEM and msg starting "Update verfügbar"
      const cat  = (ev.category || ev.cat  || "").toString();
      const msg  = (ev.message  || ev.msg  || "").toString();
      const data = ev.data || ev.payload || {};

      if (cat.toUpperCase() === "SYSTEM" && /update verf[uü]gbar/i.test(msg)) {
        open(data);
        return;
      }

      // Server explicit responses to our cmds
      if (ev.t === "cmd_result") {
        const name = (ev.name || "").toString();
        if (name === "update.install") {
          const ok   = !!ev.ok;
          const step = (ev.step || ev.detail || "").toString();
          if (ok && step === "done") {
            progressTxt.textContent = "Update installiert";
            progressSub.textContent = "Service wird neu gestartet…";
            setTimeout(close, 2500);
          } else if (!ok) {
            progressTxt.textContent = "Installation fehlgeschlagen";
            progressSub.textContent = (ev.error || "siehe service-bg.log");
            installBtn.disabled = false;
            laterBtn.disabled   = false;
            skipBtn.disabled    = false;
            closeBtn.disabled   = false;
          } else if (step) {
            progressSub.textContent = step;
          }
        }
      }
    });
  }
  tryWireBridge();

  // ----- DEBUG: window.AegisUpdater.show(meta) for manual testing -----
  window.AegisUpdater = {
    open: open,
    close: close,
    _demo: function () {
      open({
        version: "v2.0.1",
        current: "2.0.0",
        size_bytes: 161024,
        sha256: "19fbaf30f6ccd663e07552b5601176dd168cefdcf449221ce2c8d97ea9471766",
        signature_verified: true,
        signature_reason: "Sigstore-verified (Rekor-logged)",
        release_notes:
          "Improved heuristic engine\nFaster signature matching\nMinor UI polish",
        expected_repo: "user0346/aegis"
      });
    }
  };
})();
