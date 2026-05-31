function set(id, v) { const e = document.getElementById(id); if (e) e.textContent = (v == null ? 0 : v); }

chrome.runtime.sendMessage({ kind: "stats" }, (s) => {
  if (chrome.runtime.lastError || !s) return;
  set("s-warned", s.warnedNav); set("s-dl", s.blockedDownloads);
});
chrome.runtime.sendMessage({ kind: "blocklist" }, (l) => {
  if (chrome.runtime.lastError || !l) return;
  set("s-block", l.length);
});

// ---- Live-Verbindungsstatus (Bruecke + Desktop-Service) ----
function setDot(dotId, txtId, up) {
  const d = document.getElementById(dotId), t = document.getElementById(txtId);
  if (d) d.className = "dot " + (up ? "on" : "off");
  if (t) { t.textContent = up ? "verbunden" : "getrennt"; t.className = "conn-state " + (up ? "s-on" : "s-off"); }
}
function renderConn() {
  chrome.runtime.sendMessage({ kind: "native_status" }, (st) => {
    if (chrome.runtime.lastError || !st) { setDot("d-bridge","t-bridge",false); setDot("d-service","t-service",false); return; }
    setDot("d-bridge", "t-bridge", !!st.bridge);
    setDot("d-service", "t-service", !!st.service);
  });
}
renderConn();
setInterval(renderConn, 3000);

// ---- Ausnahmen (per "Trotzdem fortfahren" erlaubte Domains) ----
function renderExc() {
  chrome.runtime.sendMessage({ kind: "allow_list" }, (list) => {
    if (chrome.runtime.lastError) return;
    list = list || [];
    const wrap = document.getElementById("exc-wrap");
    const el = document.getElementById("exc-list");
    if (!list.length) { wrap.style.display = "none"; return; }
    wrap.style.display = "block";
    el.textContent = "";
    list.forEach((host) => {
      const row = document.createElement("div"); row.className = "exc-row";
      const span = document.createElement("span"); span.textContent = host;
      const btn = document.createElement("button"); btn.textContent = "✕";
      btn.title = "Wieder blockieren";
      btn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ kind: "allow_remove", host }, () => renderExc());
      });
      row.appendChild(span); row.appendChild(btn); el.appendChild(row);
    });
  });
}
document.getElementById("exc-clear").addEventListener("click", () => {
  chrome.runtime.sendMessage({ kind: "allow_clear" }, () => renderExc());
});
renderExc();
