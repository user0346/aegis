import { BLOCKLIST } from "./blocklist.js";

const BLOCKSET = new Set(BLOCKLIST.map(d => d.toLowerCase()));
const EXEC_EXT = [".exe",".scr",".bat",".cmd",".com",".ps1",".vbs",".jse",".js",".jar",".msi",".pif",".hta",".wsf"];

function hostBlocked(host) {
  host = (host || "").toLowerCase();
  if (BLOCKSET.has(host)) return true;
  for (const d of BLOCKSET) { if (host.endsWith("." + d)) return true; }
  return false;
}
async function getAllow() { const r = await chrome.storage.local.get("allow"); return new Set(r.allow || []); }
async function bump(key) {
  const r = await chrome.storage.local.get("stats"); const s = r.stats || {};
  s[key] = (s[key] || 0) + 1; await chrome.storage.local.set({ stats: s });
}

// Main-Frame: verdaechtige Navigation -> Warn-Seite (mit URL + Allowlist-Option)
chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0) return;
  let host = ""; try { host = new URL(d.url).hostname; } catch (e) { return; }
  if (!hostBlocked(host)) return;
  if ((await getAllow()).has(host)) return;
  await bump("warnedNav");
  pushNative({ t: "blocked_nav", host, url: d.url });
  const warn = chrome.runtime.getURL("warn.html") + "?b=" + encodeURIComponent(d.url) + "&h=" + encodeURIComponent(host);
  chrome.tabs.update(d.tabId, { url: warn });
});

// Risiko-Downloads stoppen
chrome.downloads.onCreated.addListener(async (item) => {
  try {
    const url = item.finalUrl || item.url || "";
    const fn = (item.filename || url).toLowerCase();
    let host = ""; try { host = new URL(url).hostname.toLowerCase(); } catch (e) {}
    if (EXEC_EXT.some(e => fn.endsWith(e)) && hostBlocked(host)) {
      chrome.downloads.cancel(item.id);
      await bump("blockedDownloads");
      pushNative({ t: "blocked_download", host, file: fn });
      chrome.notifications.create({ type: "basic", iconUrl: "icons/icon-48.png",
        title: "AEGIS Guard", message: "Download von Risiko-Domain gestoppt: " + host });
    }
  } catch (e) {}
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (!msg) return;
  if (msg.kind === "stats") { chrome.storage.local.get("stats").then(r => reply(r.stats || {})); return true; }
  if (msg.kind === "blocklist") { reply(Array.from(BLOCKSET)); return true; }
  if (msg.kind === "allow" && msg.host) {
    chrome.storage.local.get("allow").then(r => {
      const a = new Set(r.allow || []); a.add(msg.host);
      chrome.storage.local.set({ allow: Array.from(a) }).then(() => reply({ ok: true }));
    }); return true;
  }
  if (msg.kind === "allow_list") { chrome.storage.local.get("allow").then(r => reply(r.allow || [])); return true; }
  if (msg.kind === "allow_remove" && msg.host) {
    chrome.storage.local.get("allow").then(r => {
      const a = (r.allow || []).filter(x => x !== msg.host);
      chrome.storage.local.set({ allow: a }).then(() => reply({ ok: true, allow: a }));
    }); return true;
  }
  if (msg.kind === "allow_clear") { chrome.storage.local.set({ allow: [] }).then(() => reply({ ok: true })); return true; }
  if (msg.kind === "native_status") { reply({ bridge: bridgeUp, service: serviceUp }); return true; }
});

// ---- Native Messaging: Kopplung an die AEGIS-Desktop-App ----
// Robust (2026): schneller Reconnect mit Backoff (3s..30s) statt starrer 60s, Wieder-
// verbinden nach MV3-Service-Worker-Schlaf (chrome.alarms + onStartup/onInstalled), und
// bridgeUp wird erst nach ECHTER Host-Antwort true (nicht optimistisch beim Verbinden).
const EXT_VERSION = chrome.runtime.getManifest().version;   // einzige Versions-Quelle = Manifest
let nativePort = null;
let bridgeUp = false;    // Extension  <-> Native-Host (erst true, wenn der Host antwortet)
let serviceUp = false;   // Native-Host <-> Desktop-Service
let reconnectDelay = 3000;
let reconnectTimer = null;

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => { reconnectTimer = null; connectNative(); }, reconnectDelay);
  reconnectDelay = Math.min(reconnectDelay * 2, 30000);     // exponentiell bis max 30s
}
function connectNative() {
  if (nativePort) return;
  try {
    nativePort = chrome.runtime.connectNative("com.aegis.guard");
    nativePort.onMessage.addListener((m) => {
      bridgeUp = true;                  // erst jetzt ist die Bruecke nachweislich da
      reconnectDelay = 3000;            // erfolgreiche Verbindung -> Backoff zuruecksetzen
      if (!m) return;
      if (m.cmd) { handleBrowserCmd(m); return; }   // Browser-Control-Befehl von der Desktop-App
      if (Array.isArray(m.blocklist)) {
        m.blocklist.forEach(d => BLOCKSET.add(String(d).toLowerCase()));
        syncDnrRules();                 // neue Domains auch auf Netzwerkebene blocken
      }
      if (typeof m.service_online === "boolean") serviceUp = m.service_online;
    });
    nativePort.onDisconnect.addListener(() => {
      void chrome.runtime.lastError;
      nativePort = null; bridgeUp = false; serviceUp = false;
      scheduleReconnect();
    });
    try { nativePort.postMessage({ t: "hello", ext: "AEGIS Guard " + EXT_VERSION }); }
    catch (e) { void chrome.runtime.lastError; }
  } catch (e) { nativePort = null; bridgeUp = false; serviceUp = false; scheduleReconnect(); }
}
function pushNative(ev) { try { if (nativePort) nativePort.postMessage(ev); } catch (e) {} }

// ===== Browser-Control: Befehle der Desktop-App ausfuehren (Allow-List, sicher) =====
// Nur diese Befehle sind erlaubt. KEIN beliebiger Code, KEINE Passwort-/Formular-Aktionen.
const BC_ALLOWED = new Set(["media", "open_url", "list_tabs", "now_playing", "close_url"]);
const BC_MEDIA_HOSTS = ["*://*.youtube.com/*", "*://music.youtube.com/*",
  "*://open.spotify.com/*", "*://*.soundcloud.com/*", "*://*.twitch.tv/*", "*://*.netflix.com/*"];

function bcNorm(u) { return String(u || "").replace(/[#?].*$/, "").replace(/\/+$/, "").toLowerCase(); }

async function bcAudibleTab() {
  let tabs = await chrome.tabs.query({ audible: true });
  if (!tabs.length) tabs = await chrome.tabs.query({ url: BC_MEDIA_HOSTS });
  return tabs[0] || null;
}

// Laeuft im MAIN world der Seite (serialisiert -> keine Closures, nur args):
function bcMediaInPage(action) {
  const els = Array.from(document.querySelectorAll("video,audio"));
  const v = els.find(e => !e.paused && e.currentTime > 0) || els[0];
  if (!v) return false;
  if (action === "pause") v.pause();
  else if (action === "play") { v.play().catch(() => {}); }
  else if (action === "stop") { v.pause(); }
  else { v.paused ? v.play().catch(() => {}) : v.pause(); }   // playpause-Toggle
  return true;
}
function bcNowPlayingInPage() {
  const ms = navigator.mediaSession, md = ms && ms.metadata;
  const els = Array.from(document.querySelectorAll("video,audio"));
  const v = els.find(e => !e.paused) || els[0];
  return {
    state: (ms && ms.playbackState) || (v ? (v.paused ? "paused" : "playing") : "none"),
    title: md && md.title, artist: md && md.artist, album: md && md.album
  };
}

async function handleBrowserCmd(m) {
  const res = { t: "cmd_result", id: m.id, cmd: m.cmd, ok: false };
  try {
    if (!BC_ALLOWED.has(m.cmd)) throw new Error("nicht erlaubter Befehl");
    if (m.cmd === "list_tabs") {
      const tabs = await chrome.tabs.query({});
      res.tabs = tabs.map(t => ({ url: t.url, title: t.title, active: !!t.active, audible: !!t.audible }));
      res.ok = true;
    } else if (m.cmd === "open_url") {
      const url = String(m.url || "");
      if (!/^https?:\/\//i.test(url)) throw new Error("nur http(s)");
      const all = await chrome.tabs.query({});
      const hit = all.find(t => bcNorm(t.url) === bcNorm(url));
      if (hit) {                                  // schon offen -> fokussieren statt duplizieren
        await chrome.tabs.update(hit.id, { active: true });
        try { await chrome.windows.update(hit.windowId, { focused: true }); } catch (e) {}
        res.focused = true;
      } else { await chrome.tabs.create({ url, active: true }); res.created = true; }
      res.ok = true;
    } else if (m.cmd === "close_url") {
      const all = await chrome.tabs.query({});
      const hit = all.find(t => bcNorm(t.url) === bcNorm(m.url));
      if (hit) { await chrome.tabs.remove(hit.id); res.ok = true; } else { res.error = "Tab nicht offen"; }
    } else if (m.cmd === "media") {
      const tab = await bcAudibleTab();
      if (!tab) { res.error = "kein abspielender Tab"; }
      else {
        const r = await chrome.scripting.executeScript({
          target: { tabId: tab.id }, world: "MAIN", func: bcMediaInPage, args: [String(m.action || "playpause")] });
        res.ok = !!(r && r[0] && r[0].result); res.tab = tab.title;
      }
    } else if (m.cmd === "now_playing") {
      const tab = await bcAudibleTab();
      if (!tab) { res.playing = null; res.ok = true; }
      else {
        const r = await chrome.scripting.executeScript({
          target: { tabId: tab.id }, world: "MAIN", func: bcNowPlayingInPage });
        res.playing = (r && r[0] && r[0].result) || null; res.tabTitle = tab.title; res.ok = true;
      }
    }
  } catch (e) { res.error = String((e && e.message) || e); }
  pushNative(res);   // Ergebnis zurueck an den Host -> Desktop-App
}

// Vom Host live gelieferte Domains zusaetzlich als dynamische DNR-Regeln aktiv blocken.
// rules.json ist statisch — so lernt auch der echte Netzwerk-Block neue Bedrohungen dazu.
async function syncDnrRules() {
  try {
    const have = await chrome.declarativeNetRequest.getDynamicRules();
    const haveDomains = new Set(have.map(r =>
      (r.condition && r.condition.requestDomains) ? r.condition.requestDomains[0] : null
    ).filter(Boolean));
    let id = 10000;                     // >> statische rules.json-IDs, keine Kollision
    const add = [];
    for (const d of BLOCKSET) {
      if (haveDomains.has(d)) continue;
      add.push({ id: id++, priority: 1, action: { type: "block" },
        condition: { requestDomains: [d] } });
      if (add.length >= 200) break;     // pro Sync hoechstens 200 neue Regeln
    }
    if (add.length) await chrome.declarativeNetRequest.updateDynamicRules({ addRules: add });
  } catch (e) { void chrome.runtime.lastError; }
}

// MV3-Service-Worker stirbt nach ~30s Idle -> nativePort/Timer sind dann weg. Ein Alarm
// (alle 30s) plus die Lifecycle-Hooks wecken den Worker und bauen die Bruecke automatisch
// wieder auf, statt bis zum naechsten zufaelligen Event "getrennt" anzuzeigen.
chrome.alarms.create("aegis-keepalive", { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name !== "aegis-keepalive") return;
  if (nativePort) pushNative({ t: "ping" });    // serviceUp aktuell halten
  else connectNative();                          // Bruecke wieder aufbauen
});
chrome.runtime.onStartup.addListener(connectNative);
chrome.runtime.onInstalled.addListener(connectNative);
connectNative();
