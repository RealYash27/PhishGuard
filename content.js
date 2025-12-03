
// content.js — banner UI with sources displayed
(function(){
  async function isDisabledForSite(){
    try{
      const host = location.host;
      const { allowlist = {} } = await chrome.storage.sync.get({ allowlist: {} });
      return !!allowlist[host];
    } catch(e){ return false; }
  }

  function domSignals(){
    const hasPassword = !!document.querySelector('input[type="password"]');
    let crossDomainForm = false;
    try { for (const f of document.forms){ const a=new URL(f.getAttribute('action')||'', location.href); if (a.host && a.host!==location.host){ crossDomainForm=true; break; } } } catch(e){}
    return { hasPassword, crossDomainForm };
  }
  function ensureRoot(){
    let el=document.getElementById("__phishguard_banner__");
    if(!el){ el=document.createElement("div"); el.id="__phishguard_banner__"; el.style.cssText="position:fixed;left:0;right:0;top:0;z-index:2147483647;font-family:Inter,system-ui,Arial,sans-serif;"; document.documentElement.appendChild(el); }
    return el;
  }
  async function render(sev, reasons, deep=false, sources=[]){
    if (await isDisabledForSite()) { const root=ensureRoot(); root.innerHTML=""; return; }
    const root=ensureRoot(); if(sev==="green"){ root.innerHTML=""; return; }
    const color=sev==="red"?"#2b0000":"#1c1c00", border=sev==="red"?"#ff4d4f":"#fadb14";
    const title=sev==="red"?"Phishing warning":(deep?`Deep Check${sources.length?": "+sources.join(", "):": cautious"}`:"Caution: suspicious signals");
    const li=(reasons||[]).map(r=>`<li>${r}</li>`).join("");
    root.innerHTML = `
      <div style="background:${color};color:white;border-bottom:2px solid ${border};padding:10px 14px;display:flex;gap:12px;align-items:baseline">
        <strong>${title}</strong>
        <ul style="margin:0;padding-left:18px;display:flex;gap:18px;list-style:disc">${li}</ul>
        <div style="margin-left:auto;display:flex;gap:10px">
          ${sev!=="red"?'<button id="pg-deep" style="background:#1677ff;border:none;color:white;padding:6px 10px;border-radius:6px;cursor:pointer">Deep check</button>':""}
          <button id="pg-dismiss" style="background:transparent;border:1px solid #aaa;color:#eee;padding:6px 10px;border-radius:6px;cursor:pointer">Dismiss</button>
        </div>
      </div>`;
    document.getElementById("pg-dismiss").onclick=()=>{root.innerHTML="";};
    const btn=document.getElementById("pg-deep"); if(btn){ btn.onclick=()=>chrome.runtime.sendMessage({type:"DEEP_CHECK", url:location.href, dom:domSignals()}, res=>render(res.severity,res.reasons,true,res.sources||[])); }
  }
  function notify(){ chrome.runtime.sendMessage({type:"PAGE_LOADED", url:location.href, dom:domSignals()}, ()=>{}); }
  document.addEventListener("submit", async e=>{ 
    if (await isDisabledForSite()) return;
    const r=document.getElementById("__phishguard_banner__");
    if(r && r.textContent.includes("Phishing warning")){
      e.preventDefault(); e.stopImmediatePropagation();
      alert("This page looks dangerous. Dismiss the banner to proceed (not recommended).");
    }
  }, true);
  chrome.runtime.onMessage.addListener(msg=>{ 
  if(msg.type==="VERDICT") render(msg.severity,msg.reasons,!!msg.deep,msg.sources||[]);
  if(msg.type==="ALLOWLIST_UPDATED") { try { if(msg.host===location.host){ const r=document.getElementById("__phishguard_banner__"); if(r) r.innerHTML=""; } } catch(e){} }
});
  notify(); const p=history.pushState, r=history.replaceState; const hook=fn=>function(){const rv=fn.apply(this,arguments); setTimeout(notify,200); return rv;}; history.pushState=hook(p); history.replaceState=hook(r); addEventListener("popstate",()=>setTimeout(notify,200));
})();
