
const $ = (id) => document.getElementById(id);

function getHost(url){
  try { return new URL(url).hostname; } catch { return ""; }
}

async function dohQuery(name, type, provider="google"){
  const base = provider==="cloudflare" ? "https://cloudflare-dns.com/dns-query" : "https://dns.google/resolve";
  const url = provider==="cloudflare"
    ? `${base}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`
    : `${base}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetch(url, { headers: provider==="cloudflare" ? { "accept":"application/dns-json" } : {} });
  if (!res.ok) throw new Error(`DoH ${provider} ${type} failed`);
  return res.json();
}

function extractDnsAnswers(json){
  const ans = Array.isArray(json?.Answer) ? json.Answer : Array.isArray(json?.answer) ? json.answer : [];
  // google: {Answer:[{type,name,data,TTL}]}; cloudflare: {Answer:[...]} too
  const out = [];
  for (const a of ans){
    const data = String(a.data || a.Data || "").trim();
    if (data) out.push({ type: a.type, data });
  }
  return out;
}

async function resolveHostToIps(host){
  // Try both providers; tolerate failures.
  const providers = ["google","cloudflare"];
  const ip4 = [];
  const ip6 = [];
  const cnames = [];
  for (const p of providers){
    try{
      const a = await dohQuery(host, "A", p);
      for (const r of extractDnsAnswers(a)) if (String(r.type)==="1") ip4.push(r.data);
    }catch{}
    try{
      const aaaa = await dohQuery(host, "AAAA", p);
      for (const r of extractDnsAnswers(aaaa)) if (String(r.type)==="28") ip6.push(r.data);
    }catch{}
    try{
      const c = await dohQuery(host, "CNAME", p);
      for (const r of extractDnsAnswers(c)) if (String(r.type)==="5") cnames.push(r.data.replace(/\.$/,""));
    }catch{}
  }
  // Dedup
  const dedup = (arr) => Array.from(new Set(arr));
  return { ip4: dedup(ip4), ip6: dedup(ip6), cnames: dedup(cnames) };
}

async function geoFromIp(ip){
  // Prefer ipwho.is (simple, no key). Fallback ipapi.co.
  try{
    const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}?fields=success,country,country_code`);
    const j = await r.json();
    if (j && (j.success===true || j.success===undefined) && j.country_code){
      return { cc: String(j.country_code).toUpperCase(), country: j.country ? String(j.country) : "" };
    }
  }catch{}
  try{
    const r = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`);
    const j = await r.json();
    if (j && j.country_code){
      return { cc: String(j.country_code).toUpperCase(), country: j.country_name ? String(j.country_name) : "" };
    }
  }catch{}
  return null;
}

async function countryForHost(host){
  // 1) DNS resolve -> IP -> Geo
  try{
    const { ip4, ip6, cnames } = await resolveHostToIps(host);
    const bestHost = cnames[0] || host;
    const ip = ip4[0] || ip6[0] || null;
    let geo = null;
    if (ip) geo = await geoFromIp(ip);
    // 2) fallback to cc from TLD
    const ccTld = getCountryFromTld(bestHost);
    return { host: bestHost, ip, geo, cc: geo?.cc || ccTld || "", country: geo?.country || "" };
  }catch{
    const ccTld = getCountryFromTld(host);
    return { host, ip:null, geo:null, cc: ccTld || "", country:"" };
  }
}

function getCountryFromTld(host){
  const tld = (host.split(".").pop() || "").toLowerCase();
  const map = { in:"IN", us:"US", uk:"GB", au:"AU", ca:"CA", de:"DE", fr:"FR", jp:"JP" };
  return map[tld] || "";
}
function flagUrl(cc){
  return `https://flagcdn.com/w40/${cc.toLowerCase()}.png`;
}
function setRisk(sev, score){
  const dot = $("riskDot");
  const text = $("riskText");
  if (sev === "red"){ dot.className="dot bad"; text.textContent = `High risk • score ${score.toFixed(2)}`; }
  else if (sev === "yellow"){ dot.className="dot warn"; text.textContent = `Suspicious • score ${score.toFixed(2)}`; }
  else if (sev === "green"){ dot.className="dot ok"; text.textContent = `Low risk • score ${score.toFixed(2)}`; }
  else { dot.className="dot warn"; text.textContent = "Unknown"; }
}
function renderReasons(reasons){
  const ul = $("reasons");
  ul.innerHTML = "";
  (reasons || []).slice(0, 6).forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    ul.appendChild(li);
  });
}
function setProviderStatus(elStatus, elNote, status, note){
  $(elStatus).textContent = status || "—";
  $(elNote).textContent = note || "—";
}
async function getAllowlist(){
  const { allowlist = {} } = await chrome.storage.sync.get({ allowlist: {} });
  return allowlist;
}
async function isAllowlisted(host){
  const allowlist = await getAllowlist();
  return !!allowlist[host];
}
async function setAllowlisted(host, disabled){
  const allowlist = await getAllowlist();
  if (disabled) allowlist[host] = true;
  else delete allowlist[host];
  await chrome.storage.sync.set({ allowlist });

  chrome.tabs.query({active:true,currentWindow:true}, tabs => {
    const tabId = tabs?.[0]?.id;
    if (tabId) chrome.tabs.sendMessage(tabId, { type:"ALLOWLIST_UPDATED", host });
  });
}

async function fillSiteReport(url){
  const host0 = getHost(url);
  $("domain").textContent = host0 || "—";
  $("domain").onclick = () => { if (url) chrome.tabs.create({ url }); };

  $("host").textContent = host0 || "—";
  $("country").textContent = host0 ? "Resolving…" : "Unknown";
  $("flag").style.display = "none";

  if (host0){
    const info = await countryForHost(host0);
    if (info.host) $("host").textContent = info.host;

    const cc = info.cc || "";
    if (cc){
      const img = $("flag");
      img.src = flagUrl(cc);
      img.style.display = "inline-block";
      $("country").textContent = info.country ? `${info.country} (${cc})` : cc;
    } else {
      $("country").textContent = "Unknown";
      $("flag").style.display = "none";
    }
  }

  $("open-vt").onclick = (e) => {
    e.preventDefault();
    if (host0) chrome.tabs.create({ url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(host0)}` });
  };
}

function renderFromResponse(res){
  if (!res) return;
  setRisk(res.severity, res.score ?? 0);
  renderReasons(res.reasons || []);

  const sources = (res.sources || []).map(s => String(s).toLowerCase());

  const vtHit  = sources.some(s => s.includes("virus"));
  const psHit  = sources.some(s => s.includes("phishstats"));
  const usHit  = sources.some(s => s.includes("urlscan"));

  const vtReason = (res.reasons || []).find(r => r.toLowerCase().includes("virustotal"));
  setProviderStatus("vtStatus","vtNote",
    vtHit ? "Flagged" : "No hit",
    vtHit ? (vtReason || "Flagged by VirusTotal") : "No match");

  const psReason = (res.reasons || []).find(r => r.toLowerCase().includes("phishstats"));
  setProviderStatus("psStatus","psNote",
    psHit ? "Flagged" : "No hit",
    psHit ? (psReason || "Found in PhishStats") : "No match");

  const usReason = (res.reasons || []).find(r => r.toLowerCase().includes("urlscan"));
  setProviderStatus("usStatus","usNote",
    usHit ? "Flagged" : "No hit",
    usHit ? (usReason || "urlscan.io has phishing-tagged scans") : "No match");
}

document.addEventListener("DOMContentLoaded", async () => {
  $("open-options").onclick = (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); };

  chrome.tabs.query({active:true,currentWindow:true}, async tabs => {
    const t = tabs?.[0];
    const url = t && t.url && (/^https?:/.test(t.url) || /^file:/.test(t.url)) ? t.url : "";
    await fillSiteReport(url);

    const host = getHost(url);
    $("disableToggle").checked = await isAllowlisted(host);
    $("disableToggle").addEventListener("change", async (e) => {
      await setAllowlisted(host, e.target.checked);
    });

    $("quick").onclick = () => {
      if(!url) return;
      chrome.runtime.sendMessage({ type:"MANUAL_CHECK", url }, res => renderFromResponse(res));
    };
    $("deepCheck").onclick = () => {
      if(!url) return;
      $("deepCheck").textContent = "Checking...";
      $("deepCheck").disabled = true;
      chrome.runtime.sendMessage({ type:"DEEP_CHECK", url }, res => {
        renderFromResponse(res);
        $("deepCheck").textContent = "Deep Check";
        $("deepCheck").disabled = false;
      });
    };

    if (url){
      chrome.runtime.sendMessage({ type:"MANUAL_CHECK", url }, res => renderFromResponse(res));
    }
  });
});
