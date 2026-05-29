/* ============================================================
   AEGIS V2 — Panels & Controls (v2.1.0)
   Network · Quarantine · Scan · Settings · Consent
   + custom Dropdowns, Toggles, API-Key-Auge (kein Leak).
   Eigener eventReceived-Slot (Qt erlaubt mehrere).
   ============================================================ */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const setTxt = (id,v)=>{const e=$(id); if(e) e.textContent=(v==null?"0":v);};
  const selVal = (id)=>{const e=$(id); return e?e.value:"";};
  function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
  function sendCmd(name,args){ if(window.aegis&&typeof window.aegis.cmd==="function"){ try{window.aegis.cmd(JSON.stringify({name:name,args:args||{}}));}catch(e){} } }

  /* ---------- custom dropdowns (replace native <select>) ---------- */
  function buildDropdowns(){
    document.querySelectorAll("select").forEach(function(sel){
      if(sel.dataset.dd) return; sel.dataset.dd="1";
      const dd=document.createElement("div"); dd.className="dd";
      const btn=document.createElement("div"); btn.className="dd-btn"; btn.tabIndex=0;
      const cap=document.createElement("span");
      const menu=document.createElement("div"); menu.className="dd-menu";
      function cur(){ const o=sel.options[sel.selectedIndex]; return o?o.textContent:""; }
      function rebuild(){ cap.textContent=cur(); menu.innerHTML="";
        Array.from(sel.options).forEach(function(o,i){
          const it=document.createElement("div"); it.className="dd-opt"+(i===sel.selectedIndex?" sel":""); it.textContent=o.textContent;
          it.addEventListener("click",function(e){ e.stopPropagation(); sel.selectedIndex=i;
            sel.dispatchEvent(new Event("input",{bubbles:true})); sel.dispatchEvent(new Event("change",{bubbles:true}));
            cap.textContent=cur(); dd.classList.remove("open"); });
          menu.appendChild(it);
        });
      }
      btn.appendChild(cap);
      btn.addEventListener("click",function(e){ e.stopPropagation();
        document.querySelectorAll(".dd.open").forEach(x=>{if(x!==dd)x.classList.remove("open");});
        if(!dd.classList.contains("open")) rebuild(); dd.classList.toggle("open"); });
      sel.parentNode.insertBefore(dd,sel); dd.appendChild(btn); dd.appendChild(menu); dd.appendChild(sel); sel.style.display="none"; rebuild();
    });
    document.addEventListener("click",()=>document.querySelectorAll(".dd.open").forEach(x=>x.classList.remove("open")));
  }

  /* ---------- custom toggles (settings checkboxes) ---------- */
  function buildToggles(){
    ["auto-q","wake-active","cloud-stt","allow-websearch","allow-shell","allow-learning"].forEach(function(id){
      const cb=$(id); if(!cb||cb.dataset.tgl) return; cb.dataset.tgl="1";
      const lbl=document.createElement("label"); lbl.className="tgl";
      const track=document.createElement("span"); track.className="track";
      const knob=document.createElement("span"); knob.className="knob";
      cb.parentNode.insertBefore(lbl,cb); lbl.appendChild(cb); lbl.appendChild(track); lbl.appendChild(knob);
    });
  }

  /* ---------- API-key eye (show/hide; never leaks stored value) ---------- */
  const EYE='<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>';
  const EYEOFF='<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.9 17.9A10 10 0 0 1 12 19C5 19 1 12 1 12a18 18 0 0 1 5-5.9M9.9 4.2A9 9 0 0 1 12 4c7 0 11 7 11 7a18 18 0 0 1-2.2 3.2m-6.7-1a3 3 0 1 1-4.2-4.3"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
  function buildKeyEyes(){
    ["vt-key","claude-key","pv-key"].forEach(function(id){
      const inp=$(id); if(!inp||inp.dataset.eye) return; inp.dataset.eye="1";
      const wrap=document.createElement("div"); wrap.className="keyfield";
      inp.parentNode.insertBefore(wrap,inp); wrap.appendChild(inp);
      const btn=document.createElement("button"); btn.type="button"; btn.className="eye"; btn.title="Anzeigen / Verbergen"; btn.setAttribute("aria-label","Anzeigen / Verbergen"); btn.innerHTML=EYE;
      btn.addEventListener("click",function(){ const show=inp.type==="password"; inp.type=show?"text":"password"; btn.innerHTML=show?EYEOFF:EYE; });
      wrap.appendChild(btn);
    });
  }

  /* ---------- Network ---------- */
  const net=new Map(); let netDirty=false;
  function onNetEvent(ev){
    const m=ev.metadata||{}; if(!m.process&&!m.pid) return;
    const pid=m.pid||0, key=String(pid)+"|"+(m.process||"?");
    let e=net.get(key); if(!e){e={process:m.process||"?",pid:pid,conns:0,remotes:new Map()};net.set(key,e);}
    e.conns++; const r=(m.raddr||"?")+(m.rport?(":"+m.rport):""); e.remotes.set(r,(e.remotes.get(r)||0)+1); netDirty=true;
  }
  function renderNet(){
    if(!netDirty) return; netDirty=false; const tb=$("net-tbody"); if(!tb) return;
    const q=(selVal("net-search")||(($("net-search")||{}).value)||"").toLowerCase();
    const rows=Array.from(net.values()).sort((a,b)=>b.conns-a.conns); const html=[];
    for(const e of rows){ let top="",tc=-1; for(const [r,c] of e.remotes){if(c>tc){tc=c;top=r;}}
      if(q && !((e.process+" "+e.pid+" "+top).toLowerCase().includes(q))) continue;
      html.push("<tr><td>"+esc(e.process)+"</td><td class='mono'>"+esc(e.pid)+"</td><td>"+e.conns+"</td><td>"+e.remotes.size+"</td><td class='mono'>"+esc(top)+"</td><td>—</td></tr>");
    }
    tb.innerHTML=html.join("")||"<tr class='empty'><td colspan='6'>Noch keine Verbindungen erfasst.</td></tr>";
  }

  /* ---------- Quarantine ---------- */
  function renderQuar(items){
    const tb=$("quarantine-tbody"); if(!tb) return;
    if(!items||!items.length){ tb.innerHTML="<tr class='empty'><td colspan='5'>Keine Dateien in Quarantaene (pending).</td></tr>"; return; }
    tb.innerHTML=items.map(function(it){
      const f=it.file||"", base=f.split(/[\\/]/).pop()||f;
      const when=it.quarantined_at?new Date(it.quarantined_at*1000).toLocaleString():"";
      if(it.orphan){
        return "<tr><td title='"+esc(f)+"'>"+esc(base)+" <span class='muted'>(lose)</span></td><td class='mono'>—</td><td>"+esc(it.reason||"")+"</td><td>"+esc(when)+
          "</td><td><button class='btn-tiny' data-qp='"+esc(it.vault_name||base)+"'>Loeschen</button></td></tr>";
      }
      return "<tr><td title='"+esc(f)+"'>"+esc(base)+"</td><td class='mono'>"+esc((it.sha256||"").slice(0,16))+"</td><td>"+esc(it.reason||"")+"</td><td>"+esc(when)+
        "</td><td><button class='btn-tiny' data-qa='"+esc(it.id)+"'>Freigeben</button> <button class='btn-tiny' data-qd='"+esc(it.id)+"'>Sperren</button> <button class='btn-tiny' data-qx='"+esc(it.id)+"'>Loeschen</button></td></tr>";
    }).join("");
    tb.querySelectorAll("button[data-qa]").forEach(b=>b.addEventListener("click",()=>{sendCmd("quarantine.approve",{id:parseInt(b.dataset.qa,10)});setTimeout(pollQuar,500);}));
    tb.querySelectorAll("button[data-qd]").forEach(b=>b.addEventListener("click",()=>{sendCmd("quarantine.deny",{id:parseInt(b.dataset.qd,10)});setTimeout(pollQuar,500);}));
    tb.querySelectorAll("button[data-qx]").forEach(b=>b.addEventListener("click",()=>{sendCmd("quarantine.delete",{id:parseInt(b.dataset.qx,10)});setTimeout(pollQuar,500);}));
    tb.querySelectorAll("button[data-qp]").forEach(b=>b.addEventListener("click",()=>{sendCmd("quarantine.purge_orphan",{name:b.dataset.qp});setTimeout(pollQuar,500);}));
  }
  function pollQuar(){ sendCmd("quarantine.list",{}); }

  /* ---------- Scan ---------- */
  let scanTimer=null;
  function scanStart(){ sendCmd("scan.start",{}); scanPoll(); if(!scanTimer) scanTimer=setInterval(scanPoll,1500); }
  function scanCancel(){ sendCmd("scan.cancel",{}); }
  function scanPoll(){ sendCmd("scan.status",{}); sendCmd("scan.items",{limit:500}); }
  function onScanStatus(d){
    const s=d.summary||{};
    setTxt("scan-stat-total",s.items_total); setTxt("scan-stat-block",s.items_block); setTxt("scan-stat-warn",s.items_warn); setTxt("scan-stat-locs",s.locations_scanned);
    let phase=d.running?"laeuft…":(s.cancelled?"abgebrochen":"fertig");
    if(!d.running && s.error) phase="fertig · uebersprungen: "+s.error;
    setTxt("scan-stat-phase",phase);
    const sc=$("scan-start"), cc=$("scan-cancel"); if(sc) sc.disabled=!!d.running; if(cc) cc.disabled=!d.running;
    const fill=$("scan-bar-fill"); if(fill){ const pct=Math.min(100,Math.round(((s.locations_scanned||0)/17)*100)); fill.style.width=(d.running&&pct<6?6:pct)+"%"; }
    if(!d.running&&scanTimer){ clearInterval(scanTimer); scanTimer=null; }
  }
  const KIND_LABEL={registry_run:"Registry-Autostart",startup_folder:"Startup-Ordner",scheduled_task:"Geplante Tasks",service:"Dienste",temp:"Temp / AppData",browser_ext:"Browser-Extensions",wmi_subscription:"WMI-Subscriptions"};
  const VORDER={block:0,warn:1,unknown:2,clean:3};
  function scanRow(it){
    const vc={block:"v-block",warn:"v-warn",unknown:"v-unknown",clean:"v-clean"}[it.verdict]||"v-unknown";
    const act=(it.verdict==="block"||it.verdict==="warn")?"<button class='btn-tiny' data-sq='"+it._idx+"'>Quar</button>":"";
    const path=it.value||it.path||"";
    return "<tr><td><span class='verdict-pill "+vc+"'>"+esc(it.verdict)+"</span></td><td>"+esc(it.kind||"")+
      "</td><td title='"+esc(it.name||"")+"'>"+esc(it.name||"")+"</td><td class='mono' title='"+esc(path)+"'>"+esc(path)+
      "</td><td title='"+esc((it.reasons||[]).join(", "))+"'>"+esc((it.reasons||[]).join(", "))+"</td><td>"+act+"</td></tr>";
  }
  function onScanItems(d){
    const tb=$("scan-tbody"); if(!tb) return; const items=d.items||[]; items.forEach((it,i)=>it._idx=i);
    const fv=selVal("scan-filter-verdict"), fk=selVal("scan-filter-kind");
    const rows=items.filter(it=>(!fv||it.verdict===fv)&&(!fk||it.kind===fk));
    if(!rows.length){ tb.innerHTML="<tr class='empty'><td colspan='6'>Noch kein Scan-Item (oder Filter leer).</td></tr>"; return; }
    const groups={}; rows.forEach(it=>{const k=it.kind||"?"; (groups[k]=groups[k]||[]).push(it);});
    const html=[];
    function gsev(g){ return Math.min.apply(null, g.map(function(it){return VORDER[it.verdict]==null?9:VORDER[it.verdict];})); }
    Object.keys(groups).sort(function(a,b){ return gsev(groups[a])-gsev(groups[b]) || a.localeCompare(b); }).forEach(function(k){
      const g=groups[k].sort((a,b)=>(VORDER[a.verdict]==null?9:VORDER[a.verdict])-(VORDER[b.verdict]==null?9:VORDER[b.verdict]));
      const nb=g.filter(x=>x.verdict==="block").length, nw=g.filter(x=>x.verdict==="warn").length;
      const tag=(nb?" · "+nb+" block":"")+(nw?" · "+nw+" warn":"");
      html.push("<tr class='scan-group'><td colspan='6'>"+esc(KIND_LABEL[k]||k)+" ("+g.length+")"+tag+"</td></tr>");
      g.slice(0,400).forEach(it=>html.push(scanRow(it)));
    });
    tb.innerHTML=html.join("");
    tb.querySelectorAll("button[data-sq]").forEach(b=>b.addEventListener("click",()=>sendCmd("scan.quarantine_item",{index:parseInt(b.dataset.sq,10)})));
  }

  /* ---------- Settings (load/save, leak-safe) ---------- */
  function loadSettings(){ sendCmd("settings.get",{}); }
  function applySettings(d){
    const set=(id,v)=>{const e=$(id); if(e) e.checked=!!v;};
    set("auto-q",d.auto_quarantine); set("wake-active",d.wake_active); set("cloud-stt",d.cloud_stt);
    set("allow-websearch",d.allow_websearch); set("allow-shell",d.allow_shell); set("allow-learning",d.allow_learning);
    const ttl=$("consent-ttl"); if(ttl) ttl.value=d.consent_ttl_min||10;
    const ph=(id,on)=>{const e=$(id); if(e&&on) e.placeholder="●●●●●●●●  (gesetzt · DPAPI-verschluesselt)";};
    ph("vt-key",d.vt_key_set); ph("claude-key",d.claude_key_set); ph("pv-key",d.pv_key_set);
  }
  function saveSettings(){
    const c=(id)=>{const e=$(id); return e?!!e.checked:false;}; const v=(id)=>{const e=$(id); return e?e.value.trim():"";};
    const args={ auto_quarantine:c("auto-q"), wake_active:c("wake-active"), cloud_stt:c("cloud-stt"),
      allow_websearch:c("allow-websearch"), allow_shell:c("allow-shell"), allow_learning:c("allow-learning") };
    const ttl=parseInt(v("consent-ttl"),10); if(!isNaN(ttl)) args.consent_ttl_min=Math.min(1440,Math.max(1,ttl));
    const vt=v("vt-key"), ck=v("claude-key"), pv=v("pv-key");
    if(vt) args.vt_api_key=vt; if(ck) args.claude_api_key=ck; if(pv) args.pv_access_key=pv;
    sendCmd("settings.save",args);
    ["vt-key","claude-key","pv-key"].forEach(id=>{const e=$(id); if(e) e.value="";});
    const b=$("save-settings"); if(b){ const o=b.textContent; b.textContent="Gespeichert ✓"; setTimeout(()=>{b.textContent=o;},1500); }
    setTimeout(loadSettings,400);
  }

  /* ---------- Consent ---------- */
  function pollConsent(){ sendCmd("consent.list",{}); }
  function renderConsent(items){
    const box=$("consent-list"), cnt=$("consent-count"); if(!box) return; if(cnt) cnt.textContent=(items||[]).length;
    if(!items||!items.length){ box.innerHTML="<div class='empty'>Keine offenen Anfragen.</div>"; return; }
    box.innerHTML=items.map(it=>"<div class='consent-item'><div><strong>"+esc(it.title||it.action||"")+"</strong><br><span class='muted'>"+esc(it.detail||it.scope||"")+"</span></div><div class='ci-actions'><button class='btn-tiny' data-ca='"+esc(it.id)+"'>OK</button><button class='btn-tiny' data-cd='"+esc(it.id)+"'>Nein</button></div></div>").join("");
    box.querySelectorAll("button[data-ca]").forEach(b=>b.addEventListener("click",()=>{sendCmd("consent.decide",{id:b.dataset.ca,decision:"approve"});setTimeout(pollConsent,400);}));
    box.querySelectorAll("button[data-cd]").forEach(b=>b.addEventListener("click",()=>{sendCmd("consent.decide",{id:b.dataset.cd,decision:"deny"});setTimeout(pollConsent,400);}));
  }

  /* ---------- Voice send (war auch unverdrahtet) ---------- */
  function onVoiceReply(d){ const t=$("voice-transcript"); if(t) t.textContent=(d&&d.voice_reply)||"(keine Antwort)"; const st=$("voice-status"); if(st) st.textContent="Antwort"; }
  function voiceSend(){ const i=$("voice-text"); if(i&&i.value.trim()){ const t=$("voice-transcript"); if(t) t.textContent="…"; const st=$("voice-status"); if(st) st.textContent="Denkt…"; sendCmd("voice.text",{text:i.value.trim()}); i.value=""; } }

  /* ---------- event ingress ---------- */
  function onEvent(ev){
    if(!ev) return;
    if(ev.t==="cmd_result"){
      if(!ev.ok||!ev.data) return;
      if(ev.name==="quarantine.list") renderQuar(ev.data.items||[]);
      else if(ev.name==="settings.get") applySettings(ev.data);
      else if(ev.name==="scan.status") onScanStatus(ev.data);
      else if(ev.name==="scan.items") onScanItems(ev.data);
      else if(ev.name==="consent.list") renderConsent(ev.data.consent_items||ev.data.items||[]);
      else if(ev.name==="voice.text") onVoiceReply(ev.data);
      return;
    }
    if(ev.severity&&ev.source==="NetworkWatcher") onNetEvent(ev);
  }

  function wireAll(){
    buildDropdowns(); buildToggles(); buildKeyEyes();
    const ns=$("net-search"); if(ns) ns.addEventListener("input",()=>{netDirty=true;renderNet();});
    const ss=$("scan-start"); if(ss) ss.addEventListener("click",scanStart);
    const cc=$("scan-cancel"); if(cc) cc.addEventListener("click",scanCancel);
    ["scan-filter-verdict","scan-filter-kind"].forEach(id=>{const e=$(id); if(e) e.addEventListener("change",()=>sendCmd("scan.items",{limit:500}));});
    const sv=$("save-settings"); if(sv) sv.addEventListener("click",saveSettings);
    const qr=$("quar-reload"); if(qr) qr.addEventListener("click",pollQuar);
    const vs=$("voice-send"); if(vs) vs.addEventListener("click",voiceSend);
    const vt=$("voice-text"); if(vt) vt.addEventListener("keydown",e=>{if(e.key==="Enter")voiceSend();});
  }

  function attach(){
    if(!window.aegis||!window.aegis.eventReceived||!window.aegis.eventReceived.connect){ setTimeout(attach,150); return; }
    window.aegis.eventReceived.connect(function(json){ let ev; try{ev=JSON.parse(json);}catch(_){return;} try{onEvent(ev);}catch(_){} });
    loadSettings(); pollQuar(); pollConsent();
    setInterval(function(){ pollQuar(); pollConsent(); },5000);
    setInterval(renderNet,1000);
  }

  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded",wireAll); else wireAll();
  attach();
  window.AegisPanels={ network:renderNet, quarantine:pollQuar, settings:loadSettings, scan:scanPoll, consent:pollConsent };
})();
