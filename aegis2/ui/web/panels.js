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
      sel.addEventListener("input",function(){ cap.textContent=cur(); });
      btn.addEventListener("click",function(e){ e.stopPropagation();
        document.querySelectorAll(".dd.open").forEach(x=>{if(x!==dd)x.classList.remove("open");});
        if(!dd.classList.contains("open")) rebuild(); dd.classList.toggle("open"); });
      sel.parentNode.insertBefore(dd,sel); dd.appendChild(btn); dd.appendChild(menu); dd.appendChild(sel); sel.style.display="none"; rebuild();
    });
    document.addEventListener("click",()=>document.querySelectorAll(".dd.open").forEach(x=>x.classList.remove("open")));
  }

  /* ---------- custom toggles (settings checkboxes) ---------- */
  function buildToggles(){
    ["auto-q","wake-active","cloud-stt","tts-enabled","allow-websearch","allow-shell","allow-learning"].forEach(function(id){
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
  let scanTimer=null,scanCollapsed={},lastScanData=null,voiceAnim=null,_scanWasRunning=false;
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
    // Läuft ein Scan (egal wie gestartet — auch per Voice)? -> UI-Poll starten, damit die Items erscheinen.
    if(d.running && !scanTimer){ scanTimer=setInterval(scanPoll,1500); }
    // Gerade fertig geworden? -> einmal kompakt melden, bei Funden klar warnen.
    if(!d.running && _scanWasRunning){
      const blk=s.items_block||0, wrn=s.items_warn||0, tot=s.items_total||0;
      const m = blk>0 ? ("⚠ "+blk+" gefährliche Funde"+(wrn?(" + "+wrn+" Warnungen"):"")+" — unten mit «Quar» isolieren!")
              : wrn>0 ? (wrn+" Warnung(en) zum Prüfen, nichts akut Gefährliches.")
              : ("✓ Sauber — nichts Gefährliches gefunden ("+tot+" Objekte geprüft).");
      setTxt("scan-stat-phase","fertig · "+m);
    }
    _scanWasRunning=!!d.running;
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
  function onScanItems(d){ lastScanData=d; renderScanItems(); }
  function renderScanItems(){
    const d=lastScanData; if(!d) return;
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
      const collapsed=!!scanCollapsed[k]; const arrow=collapsed?"\u25B6":"\u25BC";
      html.push("<tr class='scan-group' data-grp='"+esc(k)+"'><td colspan='6'>"+arrow+"  "+esc(KIND_LABEL[k]||k)+" ("+g.length+")"+tag+"</td></tr>");
      if(!collapsed){ g.slice(0,400).forEach(it=>html.push(scanRow(it))); }
    });
    tb.innerHTML=html.join("");
    tb.querySelectorAll("button[data-sq]").forEach(b=>b.addEventListener("click",(e)=>{e.stopPropagation();sendCmd("scan.quarantine_item",{index:parseInt(b.dataset.sq,10)});}));
    tb.querySelectorAll("tr.scan-group[data-grp]").forEach(h=>h.addEventListener("click",()=>{const k=h.dataset.grp;scanCollapsed[k]=!scanCollapsed[k];renderScanItems();}));
  }

  /* ---------- Settings (load/save, leak-safe) ---------- */
  function loadSettings(){ sendCmd("settings.get",{}); }
  function applySettings(d){
    const set=(id,v)=>{const e=$(id); if(e) e.checked=!!v;};
    set("auto-q",d.auto_quarantine); set("wake-active",d.wake_active); set("cloud-stt",d.cloud_stt);
    { const e=$("tts-enabled"); if(e) e.checked=(d.tts_enabled!==false); }   // default an
    const tv=$("tts-voice"); if(tv&&d.tts_voice){ tv.value=d.tts_voice; tv.dispatchEvent(new Event("input")); }
    set("allow-websearch",d.allow_websearch); set("allow-shell",d.allow_shell); set("allow-learning",d.allow_learning);
    const ttl=$("consent-ttl"); if(ttl) ttl.value=d.consent_ttl_min||10;
    const ph=(id,on)=>{const e=$(id); if(e&&on) e.placeholder="●●●●●●●●  (gesetzt · DPAPI-verschluesselt)";};
    ph("vt-key",d.vt_key_set); ph("claude-key",d.claude_key_set); ph("pv-key",d.pv_key_set);
  }
  function saveSettings(){
    const c=(id)=>{const e=$(id); return e?!!e.checked:false;}; const v=(id)=>{const e=$(id); return e?e.value.trim():"";};
    const args={ auto_quarantine:c("auto-q"), wake_active:c("wake-active"), cloud_stt:c("cloud-stt"),
      tts_enabled:c("tts-enabled"),
      allow_websearch:c("allow-websearch"), allow_shell:c("allow-shell"), allow_learning:c("allow-learning") };
    const ttl=parseInt(v("consent-ttl"),10); if(!isNaN(ttl)) args.consent_ttl_min=Math.min(1440,Math.max(1,ttl));
    const vt=v("vt-key"), ck=v("claude-key"), pv=v("pv-key");
    if(vt) args.vt_api_key=vt; if(ck) args.claude_api_key=ck; if(pv) args.pv_access_key=pv;
    sendCmd("settings.save",args);
    ["vt-key","claude-key","pv-key"].forEach(id=>{const e=$(id); if(e) e.value="";});
    const b=$("save-settings"); if(b){ const o=b.textContent; b.textContent="Gespeichert ✓"; setTimeout(()=>{b.textContent=o;},1500); }
    setTimeout(loadSettings,400);
  }
  function renderVtStatus(d){
    const el=$("vt-status"); if(!el) return; d=d||{};
    let txt, col;
    if(!d.configured){ txt="kein Key gesetzt"; col="var(--muted,#8a93a6)"; }
    else if(d.valid){ const n=(typeof d.lookups_done==="number")?d.lookups_done:0;
      txt="Gültig ✓ · "+n+" Lookups gesamt"+(d.detail?" — "+d.detail:""); col="var(--ok,#34d399)"; }
    else { txt="Ungültig — "+(d.detail||"Key prüfen"); col="var(--bad,#f87171)"; }
    el.textContent=esc(txt); el.style.color=col;
  }

  /* ---------- Consent ---------- */
  function pollConsent(){ sendCmd("consent.list",{}); }
  function renderConsent(items){
    const box=$("consent-list"), cnt=$("consent-count"); if(!box) return; if(cnt) cnt.textContent=(items||[]).length;
    if(!items||!items.length){ box.innerHTML="<div class='empty'>Keine offenen Anfragen.</div>"; return; }
    box.innerHTML=items.map(it=>"<div class='consent-item'><div style='flex:1;min-width:0;'><strong>"+esc(it.title||it.action||"")+"</strong><div class='muted' style='white-space:normal;word-break:break-word;margin-top:4px;'>"+esc(it.detail||it.scope||"")+"</div></div><div class='ci-actions'><button class='btn-tiny' data-ca='"+esc(it.id)+"'>OK</button><button class='btn-tiny' data-cd='"+esc(it.id)+"'>Nein</button></div></div>").join("");
    box.querySelectorAll("button[data-ca]").forEach(b=>b.addEventListener("click",()=>{sendCmd("consent.decide",{id:b.dataset.ca,decision:"approve"});setTimeout(pollConsent,400);}));
    box.querySelectorAll("button[data-cd]").forEach(b=>b.addEventListener("click",()=>{sendCmd("consent.decide",{id:b.dataset.cd,decision:"deny"});setTimeout(pollConsent,400);}));
  }

  /* ---------- Autonomy (Level + Owner-Pin) ---------- */
  function loadAutonomy(){ sendCmd("autonomy.status",{}); }
  function renderAutonomy(s){
    if(!s) return;
    const st=$("autonomy-status");
    let txt=(s.level_name||"OFF");
    if(s.active&&s.remaining_sec>0) txt+=" · "+Math.ceil(s.remaining_sec/60)+" min";
    if(s.auto_demoted) txt+=" · auto-zurückgestuft";
    if(st) st.textContent=txt;
    const sel=$("autonomy-level"); if(sel&&typeof s.level==="number"){ sel.value=String(s.level); sel.dispatchEvent(new Event("input",{bubbles:true})); }
    const hint=$("autonomy-hint");
    if(hint){
      if(s.has_owner_pin){ if(hint.textContent.indexOf("kein Owner-Pin")>=0) hint.textContent=""; }
      else if(!hint.textContent.trim()){ hint.textContent="Noch kein Owner-Pin gesetzt — zuerst Pin setzen, dann ist die Stufe wählbar."; }
    }
  }
  function autonomyApply(){
    const pin=(($("autonomy-pin")||{}).value||"").trim();
    const level=parseInt((($("autonomy-level")||{}).value||"0"),10);
    let ttl=parseInt((($("autonomy-ttl")||{}).value||"60"),10); if(isNaN(ttl)) ttl=60;
    if(!pin){ setTxt("autonomy-hint","Bitte Owner-Pin eingeben."); return; }
    sendCmd("autonomy.set_level",{level:level,pin:pin,ttl_minutes:Math.min(480,Math.max(1,ttl))});
    const p=$("autonomy-pin"); if(p) p.value="";
    setTimeout(loadAutonomy,500);
  }
  function autonomySetPin(){
    const pin=(($("autonomy-pin")||{}).value||"").trim();
    const oldp=(($("autonomy-oldpin")||{}).value||"").trim();
    if(pin.length<4||pin.length>64){ setTxt("autonomy-hint","Pin/Passwort muss 4–64 Zeichen sein."); return; }
    const args={pin:pin}; if(oldp) args.old_pin=oldp;
    setTxt("autonomy-hint","Pin wird gesetzt …");
    sendCmd("autonomy.set_pin",args);
    ["autonomy-pin","autonomy-oldpin"].forEach(id=>{const e=$(id); if(e) e.value="";});
    setTimeout(loadAutonomy,800);
  }
  function autonomyStop(){ sendCmd("autonomy.end_session",{}); setTimeout(loadAutonomy,500); }

  /* ---------- Lokale KI (Ollama Auto-Install) ---------- */
  let _ollamaAutoTried=false, _ollamaOK=false, _pullActive=false;
  function loadOllama(){
    // Bridge evtl. noch nicht injiziert -> selbstheilend erneut versuchen
    if(!(window.aegis&&window.aegis.ollamaStatus)){ setTimeout(loadOllama,400); return; }
    // QWebChannel-Slots mit Rueckgabe sind ASYNCHRON -> Callback statt sync-Return!
    // (sync-Aufruf gab undefined zurueck -> Card blieb ewig auf "—").
    try{
      window.aegis.ollamaStatus(function(js){
        let s={}; try{ s=JSON.parse(js||"{}"); }catch(_){ s={}; }
        renderOllama(s);
        _ollamaOK = !!s.running;
        _pullActive = !!s.pull_active;
        // installiert aber gestoppt -> einmal automatisch starten (KEIN Re-Install)
        if(s.installed&&!s.running&&!_ollamaAutoTried&&window.aegis.ollamaStart){
          _ollamaAutoTried=true;
          try{ window.aegis.ollamaStart(); }catch(e){}
          const stg=$("ollama-status"); if(stg) stg.textContent="starte Ollama …";
          setTimeout(loadOllama,4000);
        }
      });
    }catch(e){ setTimeout(loadOllama,1000); }
  }
  function renderOllama(s){
    const st=$("ollama-status"), btn=$("ollama-install");
    if(!st||!s) return;
    if(s.pull_active){ st.textContent="lädt "+(s.pull_model||"Modell")+" · "+(s.pull_pct||0)+"%"; if(btn){ btn.textContent="lädt …"; btn.disabled=true; } return; }
    if(s.running){ st.textContent = s.active_model ? ("aktiv ✓ · "+s.active_model) : "aktiv ✓"; if(btn){ btn.textContent="Aktiv ✓"; btn.disabled=true; } }
    else if(s.installed){
      st.textContent = s.model ? "installiert · gestoppt" : "installiert · Modell fehlt";
      if(btn){ btn.textContent = s.model ? "Ollama starten" : "Modell laden"; btn.disabled=false; }
    } else {
      st.textContent="nicht installiert"; if(btn){ btn.textContent="Lokale KI aktivieren"; btn.disabled=false; }
    }
  }

  /* ---------- Memory-Ansicht (was AEGIS sich dauerhaft gemerkt hat) ---------- */
  function loadMemory(){
    if(!(window.aegis&&window.aegis.memoryGet)){ setTimeout(loadMemory,400); return; }
    try{ window.aegis.memoryGet(function(js){ let d={}; try{d=JSON.parse(js||"{}");}catch(_){} renderMemory(d); }); }
    catch(e){ setTimeout(loadMemory,800); }
  }
  function renderMemory(d){
    const body=$("mem-body"); if(!body) return;
    d=d||{};
    if(d.error){ body.textContent="Gedächtnis nicht lesbar: "+d.error; return; }
    const cnt=$("mem-count"); if(cnt) cnt.textContent=(d.knowledge_count||0)+" Wissens-Einträge";
    const row=(k,v)=>"<div class='mem-row'><span class='mem-k'>"+esc(k)+"</span><span class='mem-v'>"+v+"</span></div>";
    const notes=d.notes||[], al=d.aliases||{}, ak=Object.keys(al), tc=d.top_cmds||[];
    const out=[];
    out.push(row("Anrede", d.address?esc(d.address):"—"));
    out.push(row("Weckwort", d.wake_word?esc(d.wake_word):"AEGIS (Standard)"));
    out.push(row("Notizen ("+notes.length+")", notes.length?notes.map(esc).join("<br>"):"—"));
    out.push(row("Shortcuts ("+ak.length+")", ak.length?ak.map(k=>esc(k)+" → "+esc(String(al[k]))).join("<br>"):"—"));
    out.push(row("Oft genutzt", tc.length?tc.map(esc).join(", "):"—"));
    body.innerHTML=out.join("");
  }

  /* ---------- Voice send (war auch unverdrahtet) ---------- */
  function onVoiceReply(d){ const t=$("voice-transcript"); if(t) t.textContent=(d&&d.voice_reply)||"(keine Antwort)"; const st=$("voice-status"); if(st) st.textContent="Antwort"; }
  function voiceSend(){ const i=$("voice-text"); if(i&&i.value.trim()){ const t=$("voice-transcript"); if(t) t.textContent="…"; const st=$("voice-status"); if(st) st.textContent="Denkt…"; sendCmd("voice.text",{text:i.value.trim()}); i.value=""; } }

  /* ---------- Chat-Verlauf (sichtbare Konversation) ---------- */
  function _copyToClipboard(text, btn){
    const orig = btn ? btn.textContent : "";          // echten Button-Text merken (Bubble ODER "ganzer Chat")
    function done(){ if(btn){ btn.textContent="✓ Kopiert"; setTimeout(function(){ btn.textContent=orig; }, 1200); } }
    function exec(){
      try{
        const ta=document.createElement("textarea");
        ta.value=text; ta.style.position="fixed"; ta.style.opacity="0"; ta.style.left="-9999px";
        document.body.appendChild(ta); ta.focus(); ta.select();
        document.execCommand("copy"); document.body.removeChild(ta); done();
      }catch(e){ /* still */ }
    }
    try{
      if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(text).then(done, exec); return;
      }
    }catch(e){ /* fall through */ }
    exec();
  }
  function copyWholeChat(){
    const box=$("voice-history"); if(!box) return;
    const lines=[];
    box.querySelectorAll(".bubble").forEach(function(b){
      const who = b.className.indexOf("bubble-user")>=0 ? "Du" : "AEGIS";
      const t = (b.dataset && b.dataset.text) || "";
      if(t) lines.push(who+": "+t);
    });
    if(lines.length) _copyToClipboard(lines.join("\n\n"), $("chat-copy-all"));
  }
  function pushBubble(role, text){
    text=(text==null?"":String(text)).trim(); if(!text) return;
    const box=$("voice-history"); if(!box) return;
    const cls="bubble-"+(role==="user"?"user":"aegis");
    const last=box.lastElementChild;
    if(last && last.dataset && last.dataset.text===text && last.className.indexOf(cls)>=0) return;  // dedup
    const b=document.createElement("div");
    b.className="bubble "+cls;
    b.dataset.text=text;
    const tx=document.createElement("div");
    tx.className="bubble-text";
    tx.textContent=text;                      // textContent -> XSS-sicher
    b.appendChild(tx);
    const cp=document.createElement("button");  // Kopier-Button unter JEDER Nachricht (auch eigenen)
    cp.type="button"; cp.className="bubble-copy"; cp.title="Nachricht kopieren";
    cp.textContent="⧉ Kopieren";
    cp.addEventListener("click", function(){ _copyToClipboard(text, cp); });
    b.appendChild(cp);
    box.appendChild(b);
    while(box.children.length>40) box.removeChild(box.firstChild);
    box.scrollTop=box.scrollHeight;
  }

  /* ---------- event ingress ---------- */
  function onEvent(ev){
    if(!ev) return;
    if(ev.t==="cmd_result"){
      if(!ev.ok){
        // Backend-/Validierungsfehler fuer Autonomy sichtbar machen (nicht verschlucken)
        if(ev.name&&ev.name.indexOf("autonomy.")===0)
          setTxt("autonomy-hint","Fehler: "+(ev.error||"unbekannt"));
        return;
      }
      if(!ev.data) return;
      if(ev.name==="quarantine.list") renderQuar(ev.data.items||[]);
      else if(ev.name==="settings.get") applySettings(ev.data);
      else if(ev.name==="scan.status") onScanStatus(ev.data);
      else if(ev.name==="scan.items") onScanItems(ev.data);
      else if(ev.name==="consent.list") renderConsent(ev.data.consent_items||ev.data.items||[]);
      else if(ev.name==="voice.text") onVoiceReply(ev.data);
      else if(ev.name==="autonomy.status") renderAutonomy(ev.data);
      else if(ev.name==="autonomy.set_level"){ if(ev.data&&ev.data.status) renderAutonomy(ev.data.status); setTxt("autonomy-hint",(ev.data&&ev.data.ok)?"Stufe gesetzt.":("Abgelehnt: "+((ev.data&&ev.data.msg)||"?"))); }
      else if(ev.name==="autonomy.set_pin") setTxt("autonomy-hint",(ev.data&&ev.data.ok)?"✓ Pin gesetzt — Stufe jetzt wählbar":("Pin abgelehnt: "+((ev.data&&ev.data.msg)||"?")));
      else if(ev.name==="autonomy.end_session") loadAutonomy();
      else if(ev.name==="vt.status") renderVtStatus(ev.data);
      return;
    }
    if(ev.severity&&ev.source==="NetworkWatcher") onNetEvent(ev);
    // echtes Live-Event -> Gehirn feuert den passenden Waechter-Knoten (data-driven)
    if(ev.category && window.AegisBrain && window.AegisBrain.activateForEvent){
      try{ window.AegisBrain.activateForEvent(ev); }catch(e){}
    }
  }

  function wireAll(){
    buildDropdowns(); buildToggles(); buildKeyEyes();
    const ns=$("net-search"); if(ns) ns.addEventListener("input",()=>{netDirty=true;renderNet();});
    // ---- Voice ----
    function voiceSendText(){ const i=$("voice-text"); if(!i||!i.value.trim()||window._aegisVoiceBusy) return;
      const t=i.value.trim(); i.value=""; setTxt("voice-transcript",t); pushBubble("user",t);
      setVoiceState("thinking");                 // sofort sperren + "denkt nach" anzeigen
      if(window._busyFailsafe) clearTimeout(window._busyFailsafe);
      window._busyFailsafe=setTimeout(function(){ setVoiceState("idle"); },135000);  // Notbremse (>LLM-Timeout)
      if(window.aegis&&window.aegis.voiceText){ try{ window.aegis.voiceText(t); }catch(e){} } }
    const vsend=$("voice-send"); if(vsend) vsend.addEventListener("click",voiceSendText);
    const ccopy=$("chat-copy-all"); if(ccopy) ccopy.addEventListener("click",copyWholeChat);
    const vinp=$("voice-text"); if(vinp) vinp.addEventListener("keydown",e=>{ if(e.key==="Enter") voiceSendText(); });
    const vmic=$("voice-mic"); if(vmic) vmic.addEventListener("click",()=>{ setTxt("voice-status","Hoere zu \u2026"); if(window.aegis&&window.aegis.voiceListen){ try{ window.aegis.voiceListen(); }catch(e){} } });
    const vstop=$("voice-stop"); if(vstop) vstop.addEventListener("click",()=>{ if(window.aegis&&window.aegis.stopSpeaking){ try{ window.aegis.stopSpeaking(); }catch(e){} } setTxt("voice-status","Abgebrochen"); });
    function setVoiceState(st){
      const L={listening:"\ud83c\udfa4  H\u00f6re zu \u2026",thinking:"\u2026 verarbeite",speaking:"\ud83d\udd0a  AEGIS spricht",idle:"Bereit"};
      window._aegisVoiceBusy=(st==="speaking"||st==="listening"||st==="thinking");
      // Eingabe sperren, solange AEGIS arbeitet -> kein Überlappen + klares "arbeitet noch"-Signal
      ["voice-text","voice-send","voice-mic"].forEach(function(id){ const e=$(id); if(e) e.disabled=window._aegisVoiceBusy; });
      if(!window._aegisVoiceBusy && window._busyFailsafe){ clearTimeout(window._busyFailsafe); window._busyFailsafe=null; }
      const _vst=$("voice-stop"); if(_vst) _vst.style.display = window._aegisVoiceBusy ? "" : "none";
      setTxt("voice-status", L[st]||st||"Bereit");
      const vs=document.querySelector(".voice-state");
      if(vs){ vs.classList.remove("vs-listening","vs-thinking","vs-speaking"); if(st&&st!=="idle") vs.classList.add("vs-"+st); }
      const mic=$("voice-mic"); if(mic) mic.classList.toggle("mic-on", st==="listening");
      // Gehirn reagiert auf den Voice-Zustand — KEIN Zufalls-Feuern mehr
      const B=window.AegisBrain;
      if(voiceAnim){ clearInterval(voiceAnim); voiceAnim=null; }
      if(B){
        if(st==="idle"){ if(B.thinking) B.thinking(false); }
        else {
          // ein echter VOICE-Impuls je Zustandswechsel (kein Intervall-Spam)
          if(B.activateForEvent){ try{ B.activateForEvent({category:"VOICE",source:st,severity:"INFO"}); }catch(e){} }
          if(B.thinking) B.thinking(true);
        }
      }
    }
    if(window.aegis&&window.aegis.voiceState&&window.aegis.voiceState.connect){
      window.aegis.voiceState.connect((kind,payload)=>{
        if(kind==="transcript"){ if(payload){ setTxt("voice-transcript","\u201E"+payload+"\u201C"); pushBubble("user",payload); } }
        else if(kind==="reply"){ if(payload){ setTxt("voice-transcript",payload); pushBubble("aegis",payload); } }
        else if(kind==="state"){ setVoiceState(payload); }
        else if(kind==="status"){ setTxt("voice-status",payload||"Bereit"); }
        else if(kind==="tab"){ if(payload&&window.AegisApp&&window.AegisApp.activateTab) window.AegisApp.activateTab(payload); }
      });
    }
    const ttsSel=$("tts-voice");
    if(ttsSel) ttsSel.addEventListener("change",()=>{ sendCmd("settings.save",{tts_voice:ttsSel.value}); });
    const ttsEn=$("tts-enabled");
    if(ttsEn) ttsEn.addEventListener("change",()=>{ sendCmd("settings.save",{tts_enabled:ttsEn.checked}); });
    const ttsTest=$("tts-test");
    if(ttsTest) ttsTest.addEventListener("click",()=>{
      const v=ttsSel?ttsSel.value:""; if(v) sendCmd("settings.save",{tts_voice:v});
      if(window.aegis&&window.aegis.ttsPreview){ try{ window.aegis.ttsPreview(v); }catch(e){} }
    });
    const ss=$("scan-start"); if(ss) ss.addEventListener("click",scanStart);
    const cc=$("scan-cancel"); if(cc) cc.addEventListener("click",scanCancel);
    ["scan-filter-verdict","scan-filter-kind"].forEach(id=>{const e=$(id); if(e) e.addEventListener("change",()=>sendCmd("scan.items",{limit:500}));});
    const sv=$("save-settings"); if(sv) sv.addEventListener("click",saveSettings);
    const vtt=$("vt-test"); if(vtt) vtt.addEventListener("click",()=>{
      const s=$("vt-status");
      const ke=$("vt-key"); const typed=ke?ke.value.trim():"";
      if(s){ s.textContent="Teste …"; s.style.color="var(--muted,#8a93a6)"; }
      // gerade eingetippten Key mittesten (vor dem Speichern); leer -> Backend meldet klar
      sendCmd("vt.status", typed ? {vt_api_key:typed} : {});
    });
    const qr=$("quar-reload"); if(qr) qr.addEventListener("click",pollQuar);
    // voice-send + Enter sind bereits oben via voiceSendText (lokaler VoiceController) gebunden.
    // Frühere Cloud-Dublette entfernt — sonst feuerten zwei Voice-Pfade pro Klick.
    const aApply=$("autonomy-apply"); if(aApply) aApply.addEventListener("click",autonomyApply);
    const aSetPin=$("autonomy-setpin"); if(aSetPin) aSetPin.addEventListener("click",autonomySetPin);
    const aStop=$("autonomy-stop"); if(aStop) aStop.addEventListener("click",autonomyStop);
    // System-Steuerung (ersetzt die .bat) — alles direkt in der App
    const _sysHint=function(t){ const e=$("system-hint"); if(e){ e.textContent=t||""; e.style.color="var(--acc,#5cc8ff)"; } };
    const sRe=$("sys-restart"); if(sRe) sRe.addEventListener("click",function(){ _sysHint("Neustart läuft … das Fenster öffnet sich gleich neu."); sendCmd("system.restart",{}); });
    const sAOn=$("sys-autostart-on"); if(sAOn) sAOn.addEventListener("click",function(){ sendCmd("system.autostart",{enable:true}); _sysHint("Autostart EIN — AEGIS startet künftig mit Windows."); });
    const sAOff=$("sys-autostart-off"); if(sAOff) sAOff.addEventListener("click",function(){ sendCmd("system.autostart",{enable:false}); _sysHint("Autostart AUS."); });
    const sRep=$("sys-repin"); if(sRep) sRep.addEventListener("click",function(){ sendCmd("system.repin",{}); _sysHint("Integritäts-Baseline wird neu gesetzt."); });
    const sSet=$("sys-setup"); if(sSet) sSet.addEventListener("click",function(){ sendCmd("system.setup",{}); _sysHint("Einrichtung/Reparatur ausgeführt (Browser-Host + Autostart + Baseline)."); });
    const oin=$("ollama-install");
    if(oin) oin.addEventListener("click",()=>{
      const w=$("ollama-progress-wrap"); if(w) w.style.display="block";
      oin.disabled=true; oin.textContent="Installiere …";
      if(window.aegis&&window.aegis.ollamaInstall){ try{ window.aegis.ollamaInstall(); }catch(e){} }
    });
    if(window.aegis&&window.aegis.ollamaProgress&&window.aegis.ollamaProgress.connect){
      window.aegis.ollamaProgress.connect((stage,pct)=>{
        const bar=$("ollama-bar"), stg=$("ollama-stage"), btn=$("ollama-install");
        if(stg) stg.textContent=stage||"";
        if(pct>=0&&bar) bar.style.width=Math.min(100,pct)+"%";
        if(pct===100){ if(btn) btn.textContent="Aktiv ✓"; setTimeout(loadOllama,1500); }
        else if(pct===-1){ if(btn){ btn.disabled=false; btn.textContent="Erneut versuchen"; } if(bar) bar.style.background="#f87171"; }
      });
    }
  }

  function attach(){
    if(!window.aegis||!window.aegis.eventReceived||!window.aegis.eventReceived.connect){ setTimeout(attach,150); return; }
    window.aegis.eventReceived.connect(function(json){ let ev; try{ev=JSON.parse(json);}catch(_){return;} try{onEvent(ev);}catch(_){} });
    loadSettings(); pollQuar(); pollConsent(); loadAutonomy(); loadOllama();
    setInterval(function(){ pollQuar(); pollConsent(); loadMemory(); if(!_ollamaOK || _pullActive) loadOllama(); },5000);
    setInterval(renderNet,1000);
  }

  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded",wireAll); else wireAll();
  attach();
  window.AegisPanels={ network:renderNet, quarantine:pollQuar, settings:function(){loadSettings();loadAutonomy();loadOllama();}, scan:scanPoll, consent:pollConsent, voice:loadOllama, memory:loadMemory };
})();
