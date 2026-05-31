const p = new URLSearchParams(location.search);
const b = p.get("b") || ""; const h = p.get("h") || "";
document.getElementById("host").textContent = h || "(unbekannt)";
document.getElementById("full").textContent = b;
document.getElementById("back").addEventListener("click", () => {
  if (history.length > 1) history.back(); else window.close();
});
document.getElementById("proceed").addEventListener("click", () => {
  if (!h || !b) return;
  chrome.runtime.sendMessage({ kind: "allow", host: h }, () => { location.href = b; });
});
