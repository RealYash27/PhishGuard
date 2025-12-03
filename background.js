
// background.js — GSB v5 + VirusTotal + PhishStats + urlscan
let MODEL = null;

// ---- Settings ----
async function getAllowlist(){
  const { allowlist = {} } = await chrome.storage.sync.get({ allowlist: {} });
  return allowlist;
}
async function isAllowlisted(url){
  try{
    const host = new URL(url).hostname;
    const allowlist = await getAllowlist();
    return !!allowlist[host];
  } catch(e){ return false; }
}

async function getSettings(){
  return await chrome.storage.sync.get({
    onlineDeepChecksEnabled: false,
    vtKey: "",
    urlscanKey: ""
  });
}

// ---- Model ----
async function loadModel() {
  if (MODEL) return MODEL;
  try {
    MODEL = await (await fetch(chrome.runtime.getURL("model/lr_model.json"))).json();
  } catch {
    MODEL = { features:[], weights:[], bias:0, scaler:{mean:[],std:[]}, numeric_indices:[] };
  }
  return MODEL;
}

// ---- Features & heuristics ----
function shannonEntropy(s){ const f={}; for (const c of s) f[c]=(f[c]||0)+1; const n=s.length||1; let H=0; for (const k in f){const p=f[k]/n; H-=p*Math.log2(p);} return Math.min(1,H/5); }
function isIPv4(h){ return /^\d{1,3}(\.\d{1,3}){3}$/.test(h); }
const RARE_TLDS = new Set(["top","xyz","online","club","support","live","shop","buzz","monster","click","gq","cf","ml","tk"]);
function computeUrlFeatures(raw){
  let u; try{u=new URL(raw);}catch{return null;}
  const host=u.hostname, path=u.pathname||"", dots=(host.match(/\./g)||[]).length, qn=Array.from(new URLSearchParams(u.search)).length;
  return { host_len:host.length, path_len:path.length, dots:dots, qparams:qn,
    subdomain_depth:Math.max(0, host.split(".").length-2),
    entropy: shannonEntropy(host.replace(/\./g,"")),
    has_at: raw.includes("@")?1:0, ip_host: isIPv4(host)?1:0,
    has_punycode: host.includes("xn--")?1:0, http_not_https: (u.protocol!=="https:")?1:0,
    tld_rare: RARE_TLDS.has((host.split(".").pop()||"").toLowerCase()),
    host, path, href: raw };
}
function heuristicScore(f, dom){
  if(!f) return 0; let s=0;
  if(f.has_punycode) s+=.5; if(f.ip_host) s+=.4; if(f.has_at) s+=.3;
  if(f.host_len+f.path_len>100) s+=.2; if(f.dots>3) s+=.15;
  if(f.tld_rare) s+=.1; if(f.entropy>.62) s+=.15;
  if(dom?.hasPassword && f.http_not_https) s+=.25; if(dom?.crossDomainForm) s+=.25;
  return Math.min(1,s);
}
function topReasons(f, dom){
  const R=[]; if(f.has_punycode)R.push("Punycode / homoglyph domain");
  if(f.ip_host)R.push("IP address as host"); if(f.has_at)R.push("'@' present in URL");
  if(f.host_len+f.path_len>100)R.push("Very long URL"); if(f.dots>3)R.push("Deep subdomain chain");
  if(f.tld_rare)R.push("Rare/suspicious TLD"); if(f.entropy>.62)R.push("High-entropy hostname");
  if(dom?.hasPassword && f.http_not_https)R.push("Password over HTTP (no HTTPS)");
  if(dom?.crossDomainForm)R.push("Form posts to a different domain"); return R;
}
function scoreLR(feat, model){
  if(!model?.features?.length || !model?.weights?.length) return .5;
  const num = new Set(model.numeric_indices||[]), X=[];
  for(let i=0;i<model.features.length;i++){
    let v = feat[model.features[i]] ?? 0;
    if(num.has(i)){ const mu=model.scaler.mean[i]||0, sd=model.scaler.std[i]||1; v=(v-mu)/(sd||1); }
    X.push(v);
  }
  let z=model.bias||0; for(let i=0;i<X.length;i++) z+=(model.weights[i]||0)*X[i];
  return Math.min(1, Math.max(0, 1/(1+Math.exp(-z))));
}
function fuseScores(h,m,dom){ let b=.6*m+.4*h; if(dom?.crossDomainForm) b+=.25; if(dom?.hasPassword) b+=.10; return Math.max(0,Math.min(1,b)); }
function severityFromScore(s,f,dom){ if(f?.has_punycode && dom?.crossDomainForm) return "red"; if(s<=.40) return "green"; if(s<=.80) return "yellow"; return "red"; }

// ---- GSB helpers ----
function b64url(buf){ let s=btoa(String.fromCharCode.apply(null, Array.from(buf))); return s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
async function sha256Bytes(str){ const enc=new TextEncoder(); const h=await crypto.subtle.digest("SHA-256", enc.encode(str)); return new Uint8Array(h); }
function canonicalize(u){ const url=new URL(u); url.hash=""; url.username=""; url.password=""; url.hostname=url.hostname.toLowerCase(); if((url.protocol==="http:"&&url.port==="80")||(url.protocol==="https:"&&url.port==="443")) url.port=""; url.pathname=url.pathname.replace(/\/\/+/g,"/"); return url; }
function makeExpressions(u){
  const url=canonicalize(u), host=url.hostname, path=url.pathname||"/", query=url.search||"";
  const labels=host.split("."), hosts=[]; for(let i=0;i<labels.length && hosts.length<5;i++) hosts.push(labels.slice(i).join("."));
  const parts=path.split("/").filter(Boolean), prefixes=["/"]; if(parts.length){ let acc=""; for(let i=0;i<parts.length && prefixes.length<4;i++){ acc+="/"+parts[i]; prefixes.push(acc+"/"); } if(!path.endsWith("/")) prefixes.push(path); }
  const set=new Set(); for(const h of hosts) for(const p of prefixes.slice(0,4)) set.add(`${url.protocol}//${h}${p}`); set.add(`${url.protocol}//${host}${path}${query}`); return Array.from(set);
}

// ---- Providers ----
const withTimeout = (p,ms=4500)=>Promise.race([p,new Promise(r=>setTimeout(()=>r(null),ms))]);

function b64urlNoPadFromUtf8(str){ return btoa(unescape(encodeURIComponent(str))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
async function checkVirusTotal(u, key){
  if(!key) return null;
  try{
    const id = b64urlNoPadFromUtf8(u);
    let r = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, { headers:{ "x-apikey": key } });
    if (r.status === 404){
      const form = new URLSearchParams(); form.set("url", u);
      await fetch("https://www.virustotal.com/api/v3/urls", { method:"POST", headers:{ "x-apikey": key, "Content-Type":"application/x-www-form-urlencoded" }, body: form.toString() });
      return { hit:false, submitted:true, reason:"Submitted to VirusTotal (pending analysis)" };
    }
    const json = await r.json();
    const stats = json?.data?.attributes?.last_analysis_stats || {};
    const malicious = (stats.malicious||0) + (stats.suspicious||0);
    if (malicious > 0){
      return { hit:true, reason:`Flagged by VirusTotal (${malicious} vendors)`, meta: stats };
    } else {
      return { hit:false, reason:"Not flagged by VirusTotal", meta: stats };
    }
  }catch(e){
    console.warn("VirusTotal error", e);
    return null;
  }
}

async function checkPhishStats(url){
  try{
    const r=await fetch(`https://api.phishstats.info:443/api/phishing?_where=(url,eq,${encodeURIComponent(url)})`).then(r=>r.json());
    const hit=Array.isArray(r)&&r.length>0; return hit?{hit:true,reason:"Found in PhishStats (reported phishing)",meta:r[0]}:{hit:false};
  }catch(e){console.warn("PhishStats error",e); return null;}
}


async function checkUrlscan(u, key){
  if(!key) return null;
  try{
    const {hostname}=new URL(u);
    const r=await fetch(`https://urlscan.io/api/v1/search/?q=domain:${hostname}+AND+task.tags:phishing`,{headers:{"API-Key":key}}).then(r=>r.json());
    const hit=(r?.total||0)>0; return hit?{hit:true,reason:"urlscan.io has phishing-tagged scans",meta:r}:{hit:false};
  }catch(e){console.warn("urlscan error",e); return null;}
}

// ---- Deep Check ----
async function deepCheck(url, dom, base){
  const s=await getSettings();
  if(!s.onlineDeepChecksEnabled) return {delta:0,reasonsAdd:["Online Deep Check disabled"],sources:[]};
  const [vt, ps, us] = await Promise.all([
    withTimeout(checkVirusTotal(url, s.vtKey), 4500),
    withTimeout(checkPhishStats(url), 4500),
    withTimeout(checkUrlscan(url, s.urlscanKey), 4500)
  ]);
  let d=0, R=[], S=[];
  if(vt?.hit){ d+=.45; R.push(vt.reason); S.push("VirusTotal"); }
  else if (vt?.submitted){ R.push(vt.reason); S.push("VirusTotal"); }
  if(ps?.hit){ d+=.30; R.push(ps.reason); S.push("PhishStats"); }
  if(us?.hit){ d+=.15; R.push(us.reason); S.push("urlscan.io"); }
  return { delta: Math.min(1,d), reasonsAdd: Array.from(new Set(R)), sources: S };
}

// ---- Flows ----
function sendVerdict(tabId, score, sev, reasons, deep=false, sources=[]){
  const valid = Number.isInteger(tabId) && tabId >= 0;
  const payload = { type:"VERDICT", score, severity: sev, reasons, deep, sources };

  if(valid){
    chrome.tabs.sendMessage(tabId, payload).catch(()=>{});
    return;
  }

  // Fallback: try active tab (e.g., popup/options triggers without sender.tab)
  chrome.tabs.query({ active:true, lastFocusedWindow:true }).then(tabs=>{
    const id = tabs?.[0]?.id;
    if(Number.isInteger(id) && id >= 0){
      chrome.tabs.sendMessage(id, payload).catch(()=>{});
    } else {
      console.warn("sendVerdict: no valid tabId", tabId);
    }
  }).catch(()=>{});
}
async function handleAutoCheck(tabId, url, dom){
  if (await isAllowlisted(url)) {
    try{ await chrome.action.setBadgeText({tabId,text:""}); }catch{}
    sendVerdict(tabId, 0, "green", ["Protection disabled for this site"], false, []);
    return { score: 0, severity: "green", reasons: ["Protection disabled for this site"], features:null, heur:0, ml:0 };
  }

  const m=await loadModel(); const f=computeUrlFeatures(url); const h=heuristicScore(f,dom); const ml=scoreLR(f,m);
  const sc=fuseScores(h,ml,dom); const sev=severityFromScore(sc,f,dom); const reasons=topReasons(f,dom).slice(0,3);
  try{const b=sev==="green"?"":(sev==="yellow"?"!":"⚠"); await chrome.action.setBadgeText({tabId,text:b}); await chrome.action.setBadgeBackgroundColor({tabId,color:sev==="red"?"#ff4d4f":"#fadb14"});}catch{}
  sendVerdict(tabId, sc, sev, reasons, false, []);
  return { score: sc, severity: sev, reasons, features:f, heur:h, ml };
}
async function handleDeepCheck(tabId, url, dom){
  if (await isAllowlisted(url)) {
    try{ await chrome.action.setBadgeText({tabId,text:""}); }catch{}
    sendVerdict(tabId, 0, "green", ["Protection disabled for this site"], true, []);
    return { score: 0, severity: "green", reasons: ["Protection disabled for this site"], deep:true, sources: [] };
  }

  const base = await handleAutoCheck(tabId, url, dom);
  const extra = await deepCheck(url, dom, base);
  const score = Math.min(1, base.score + (extra.delta||0));
  const sev = severityFromScore(score, base.features, dom);
  const reasons = Array.from(new Set([...(base.reasons||[]), ...((extra.reasonsAdd||[]))])).slice(0,6);
  try{const b=sev==="green"?"":(sev==="yellow"?"!":"⚠"); await chrome.action.setBadgeText({tabId,text:b}); await chrome.action.setBadgeBackgroundColor({tabId,color:sev==="red"?"#ff4d4f":"#fadb14"});}catch{}
  sendVerdict(tabId, score, sev, reasons, true, extra.sources||[]);
  return { score, severity: sev, reasons, deep:true, sources: extra.sources||[] };
}
chrome.runtime.onMessage.addListener((msg,sender,sendResponse)=>{(async()=>{
  if(msg.type==="PAGE_LOADED"){ const id=sender.tab?.id; if(!id) return; const r=await handleAutoCheck(id,msg.url,msg.dom); sendResponse(r); }
  else if(msg.type==="MANUAL_CHECK"){ const r=await handleAutoCheck(sender.tab?.id, msg.url, msg.dom||null); sendResponse(r); }
  else if(msg.type==="DEEP_CHECK"){ const r=await handleDeepCheck(sender.tab?.id, msg.url, msg.dom||null); sendResponse(r); }
  else if(msg.type==="SETTINGS_GET"){ sendResponse(await getSettings()); }
})(); return true;});
