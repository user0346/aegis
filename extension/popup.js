chrome.runtime.sendMessage({ kind: "stats" }, (s) => {
  if (!s) return;
  document.getElementById("s-blocked").textContent = s.blockedNav || 0;
  document.getElementById("s-warned").textContent = s.warnedNav || 0;
  document.getElementById("s-dl").textContent = s.blockedDownloads || 0;
});
