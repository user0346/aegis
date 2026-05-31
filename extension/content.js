(function () {
  chrome.runtime.sendMessage({ kind: "blocklist" }, (list) => {
    if (chrome.runtime.lastError || !list || !list.length) return;
    const set = new Set(list);
    const blocked = (h) => {
      h = (h || "").toLowerCase();
      if (set.has(h)) return true;
      for (const d of set) { if (h.endsWith("." + d)) return true; }
      return false;
    };
    const scan = () => {
      document.querySelectorAll('a[href]:not([data-aegis])').forEach((a) => {
        a.setAttribute("data-aegis", "1");
        let h = ""; try { h = new URL(a.href).hostname; } catch (e) { return; }
        if (blocked(h)) {
          a.style.outline = "2px solid #fb923c";
          a.style.outlineOffset = "2px";
          a.title = "AEGIS: verdaechtige Domain (" + h + ")";
        }
      });
    };
    scan();
    try { new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true }); } catch (e) {}
  });
})();
