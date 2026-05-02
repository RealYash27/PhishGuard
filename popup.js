// popup.js — site report + manual URL scan + QR scan + history shortcut

const $ = (id) => document.getElementById(id);

let CURRENT_VERDICT = null;

function getHost(url) { try { return new URL(url).hostname; } catch { return ""; } }

// ---------- DNS-over-HTTPS for country lookup ----------
async function dohQuery(name, type, provider = "google") {
  const base = provider === "cloudflare" ? "https://cloudflare-dns.com/dns-query" : "https://dns.google/resolve";
  const url = `${base}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetch(url, { headers: provider === "cloudflare" ? { "accept": "application/dns-json" } : {} });
  if (!res.ok) throw new Error(`DoH ${provider} ${type} failed`);
  return res.json();
}
function extractDnsAnswers(json) {
  const ans = Array.isArray(json?.Answer) ? json.Answer : Array.isArray(json?.answer) ? json.answer : [];
  const out = [];
  for (const a of ans) {
    const data = String(a.data || a.Data || "").trim();
    if (data) out.push({ type: a.type, data });
  }
  return out;
}
async function resolveHostToIps(host) {
  const providers = ["google", "cloudflare"];
  const ip4 = [], ip6 = [], cnames = [];
  for (const p of providers) {
    try { for (const r of extractDnsAnswers(await dohQuery(host, "A", p))) if (String(r.type) === "1") ip4.push(r.data); } catch {}
    try { for (const r of extractDnsAnswers(await dohQuery(host, "AAAA", p))) if (String(r.type) === "28") ip6.push(r.data); } catch {}
    try { for (const r of extractDnsAnswers(await dohQuery(host, "CNAME", p))) if (String(r.type) === "5") cnames.push(r.data.replace(/\.$/, "")); } catch {}
  }
  const dedup = (arr) => Array.from(new Set(arr));
  return { ip4: dedup(ip4), ip6: dedup(ip6), cnames: dedup(cnames) };
}
async function geoFromIp(ip) {
  try {
    const j = await (await fetch(`https://ipwho.is/${encodeURIComponent(ip)}?fields=success,country,country_code`)).json();
    if (j && (j.success === true || j.success === undefined) && j.country_code) {
      return { cc: String(j.country_code).toUpperCase(), country: j.country ? String(j.country) : "" };
    }
  } catch {}
  try {
    const j = await (await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`)).json();
    if (j && j.country_code) {
      return { cc: String(j.country_code).toUpperCase(), country: j.country_name ? String(j.country_name) : "" };
    }
  } catch {}
  return null;
}
function getCountryFromTld(host) {
  const tld = (host.split(".").pop() || "").toLowerCase();
  const map = { in: "IN", us: "US", uk: "GB", au: "AU", ca: "CA", de: "DE", fr: "FR", jp: "JP" };
  return map[tld] || "";
}
async function countryForHost(host) {
  try {
    const { ip4, ip6, cnames } = await resolveHostToIps(host);
    const bestHost = cnames[0] || host;
    const ip = ip4[0] || ip6[0] || null;
    let geo = null;
    if (ip) geo = await geoFromIp(ip);
    const ccTld = getCountryFromTld(bestHost);
    return { host: bestHost, ip, geo, cc: geo?.cc || ccTld || "", country: geo?.country || "" };
  } catch {
    return { host, ip: null, geo: null, cc: getCountryFromTld(host) || "", country: "" };
  }
}
function flagUrl(cc) { return `https://flagcdn.com/w40/${cc.toLowerCase()}.png`; }

// ---------- Verdict rendering ----------
function setRisk(sev, score) {
  const dot = $("riskDot"), text = $("riskText");
  if (sev === "red") { dot.className = "dot bad"; text.textContent = `High risk • score ${score.toFixed(2)}`; }
  else if (sev === "yellow") { dot.className = "dot warn"; text.textContent = `Suspicious • score ${score.toFixed(2)}`; }
  else if (sev === "green") { dot.className = "dot ok"; text.textContent = `Low risk • score ${score.toFixed(2)}`; }
  else { dot.className = "dot warn"; text.textContent = "Unknown"; }
}
function renderReasons(reasons) {
  const ul = $("reasons"); ul.innerHTML = "";
  (reasons || []).slice(0, 6).forEach(r => {
    const li = document.createElement("li"); li.textContent = r; ul.appendChild(li);
  });
}
function setProviderStatus(elStatus, elNote, status, note) {
  $(elStatus).textContent = status || "—";
  $(elNote).textContent = note || "—";
}
function setProtocol(proto) {
  const el = $("protocol");
  if (proto === "https:") { el.textContent = "Yes"; el.className = "v https"; }
  else if (proto === "http:") { el.textContent = "No (HTTP)"; el.className = "v http"; }
  else { el.textContent = "—"; el.className = "v"; }
}
function setAge(ageInfo) {
  const el = $("age");
  if (!ageInfo || ageInfo.ageDays == null) { el.textContent = "—"; el.className = "v"; return; }
  const d = ageInfo.ageDays;
  el.textContent = d < 365 ? `${d} day${d === 1 ? "" : "s"}` : `${(d / 365).toFixed(1)} years`;
  el.className = "v" + (d < 90 ? " http" : (d < 365 ? "" : " https"));
}
function setTypo(typo) {
  const box = $("typoBox");
  if (!typo) { box.classList.remove("show"); box.textContent = ""; return; }
  box.classList.add("show");
  box.textContent = typo.contains
    ? `⚠ Hostname contains brand "${typo.brand}" but isn't the official site — possible impersonation.`
    : `⚠ Hostname is suspiciously similar to "${typo.brand}" (typosquatting).`;
}

// ---------- Allowlist ----------
async function getAllowlist() { const { allowlist = {} } = await chrome.storage.sync.get({ allowlist: {} }); return allowlist; }
async function isAllowlisted(host) { return !!(await getAllowlist())[host]; }
async function setAllowlisted(host, disabled) {
  const allowlist = await getAllowlist();
  if (disabled) allowlist[host] = true; else delete allowlist[host];
  await chrome.storage.sync.set({ allowlist });
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const tabId = tabs?.[0]?.id;
    if (tabId) chrome.tabs.sendMessage(tabId, { type: "ALLOWLIST_UPDATED", host }).catch(() => {});
  });
}

// ---------- Site report ----------
async function fillSiteReport(url) {
  const host0 = getHost(url);
  $("domain").textContent = host0 || "—";
  $("domain").onclick = () => { if (url) chrome.tabs.create({ url }); };

  $("host").textContent = host0 || "—";
  $("country").textContent = host0 ? "Resolving…" : "Unknown";
  $("flag").style.display = "none";

  try { setProtocol(new URL(url).protocol); } catch { setProtocol(null); }

  if (host0) {
    const info = await countryForHost(host0);
    if (info.host) $("host").textContent = info.host;
    const cc = info.cc || "";
    if (cc) {
      const img = $("flag");
      img.src = flagUrl(cc); img.style.display = "inline-block";
      $("country").textContent = info.country ? `${info.country} (${cc})` : cc;
    } else {
      $("country").textContent = "Unknown"; $("flag").style.display = "none";
    }
  }

  $("open-vt").onclick = (e) => {
    e.preventDefault();
    if (host0) chrome.tabs.create({ url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(host0)}` });
  };
}

function renderFromResponse(res) {
  if (!res) return;
  CURRENT_VERDICT = res;
  setRisk(res.severity, res.score ?? 0);
  renderReasons(res.reasons || []);
  setTypo(res.typo || null);
  if (res.protocol) setProtocol(res.protocol);
  if (res.ageInfo) setAge(res.ageInfo);

  const sources = (res.sources || []).map(s => String(s).toLowerCase());
  const vtHit = sources.some(s => s.includes("virus"));
  const psHit = sources.some(s => s.includes("phishstats"));
  const usHit = sources.some(s => s.includes("urlscan"));
  const gsbHit = sources.some(s => s.includes("safe browsing") || s.includes("gsb"));

  const find = (kw) => (res.reasons || []).find(r => r.toLowerCase().includes(kw));
  setProviderStatus("vtStatus", "vtNote",
    vtHit ? "Flagged" : "No hit",
    vtHit ? (find("virustotal") || "Flagged by VirusTotal") : "No match");
  setProviderStatus("psStatus", "psNote",
    psHit ? "Flagged" : "No hit",
    psHit ? (find("phishstats") || "Found in PhishStats") : "No match");
  setProviderStatus("usStatus", "usNote",
    usHit ? "Flagged" : "No hit",
    usHit ? (find("urlscan") || "urlscan.io has phishing-tagged scans") : "No match");
  setProviderStatus("gsbStatus", "gsbNote",
    gsbHit ? "Flagged" : "No hit",
    gsbHit ? (find("safe browsing") || "Flagged by Google Safe Browsing") : "No match");
}

// ---------- Manual URL scan ----------
function classForSeverity(sev) { return sev === "red" ? "bad" : sev === "yellow" ? "warn" : "ok"; }
async function manualScan(url) {
  const out = $("manualResult");
  out.className = "scanResult"; out.textContent = "Scanning…";
  let normalized = url.trim();
  if (!/^https?:\/\//i.test(normalized)) normalized = "http://" + normalized;
  chrome.runtime.sendMessage({ type: "MANUAL_URL_SCAN", url: normalized }, res => {
    if (!res || res.error) { out.className = "scanResult bad"; out.textContent = "Error: " + (res?.error || "scan failed"); return; }
    const label = res.severity === "red" ? "High risk"
                : res.severity === "yellow" ? "Suspicious"
                : "Looks safe";
    const reasons = (res.reasons || []).slice(0, 3).join(" · ") || "no obvious phishing signals";
    out.className = "scanResult " + classForSeverity(res.severity);
    out.textContent = `${label} (score ${res.score.toFixed(2)}) — ${reasons}`;
  });
}

// ---------- QR scan (jsQR — works on every platform, including Windows) ----------
async function decodeQrFromFile(file) {
  if (typeof jsQR !== "function") {
    return { error: "QR decoder failed to load." };
  }
  try {
    const bitmap = await createImageBitmap(file);
    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    const ctx = canvas.getContext("2d");
    ctx.drawImage(bitmap, 0, 0);
    const img = ctx.getImageData(0, 0, bitmap.width, bitmap.height);
    const code = jsQR(img.data, img.width, img.height);
    if (!code || !code.data) return { error: "No QR code found in image." };
    return { value: code.data };
  } catch (e) {
    return { error: "Failed to decode QR: " + (e.message || e) };
  }
}

async function handleQrFile(file) {
  const out = $("qrResult"); out.className = "scanResult"; out.textContent = "Decoding…";
  const r = await decodeQrFromFile(file);
  if (r.error) { out.className = "scanResult bad"; out.textContent = r.error; return; }
  const value = r.value;
  const looksLikeUrl = /^[a-z]+:\/\//i.test(value) || /\.[a-z]{2,}(\/|$)/i.test(value);
  if (!looksLikeUrl) {
    out.className = "scanResult"; out.textContent = `QR content: ${value.slice(0, 200)}`;
    return;
  }
  out.textContent = `Found URL: ${value} — scanning…`;
  let normalized = value.trim();
  if (!/^https?:\/\//i.test(normalized)) normalized = "http://" + normalized;
  chrome.runtime.sendMessage({ type: "MANUAL_URL_SCAN", url: normalized }, res => {
    if (!res || res.error) { out.className = "scanResult bad"; out.textContent = "Scan failed: " + (res?.error || "unknown"); return; }
    const label = res.severity === "red" ? "High risk"
                : res.severity === "yellow" ? "Suspicious"
                : "Looks safe";
    const reasons = (res.reasons || []).slice(0, 3).join(" · ") || "no obvious phishing signals";
    out.className = "scanResult " + classForSeverity(res.severity);
    out.textContent = `${label} — ${value.slice(0, 80)}${value.length > 80 ? "…" : ""} · ${reasons}`;
  });
}

// ---------- History (recent detections) ----------
function renderHistory(history) {
  const wrap = $("historyList");
  if (!history.length) { wrap.textContent = "No scans yet."; return; }
  wrap.innerHTML = history.slice(0, 10).map(h => {
    const cls = h.severity === "red" ? "red" : h.severity === "yellow" ? "yellow" : "green";
    const label = h.severity === "red" ? "High" : h.severity === "yellow" ? "Susp" : "Safe";
    const primary = h.download
      ? `⬇ ${escapeHtml(h.filename || "download")}`
      : escapeHtml(h.host || h.url || "—");
    return `<div class="h"><span class="host" title="${escapeAttr(h.url || h.host || "")}">${primary}</span><span class="badge ${cls}">${label}</span></div>`;
  }).join("");
}
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c])); }
function escapeAttr(s) { return escapeHtml(s); }

// ---------- Boot ----------
document.addEventListener("DOMContentLoaded", async () => {
  $("open-options").onclick = (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); };
  $("open-history").onclick = (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); };

  chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
    const t = tabs?.[0];
    const url = t && t.url && /^https?:/.test(t.url) ? t.url : "";
    await fillSiteReport(url);

    const host = getHost(url);
    $("disableToggle").checked = await isAllowlisted(host);
    $("disableToggle").addEventListener("change", async (e) => {
      await setAllowlisted(host, e.target.checked);
    });

    $("quick").onclick = () => {
      if (!url) return;
      chrome.runtime.sendMessage({ type: "MANUAL_CHECK", url }, res => renderFromResponse(res));
    };
    $("deepCheck").onclick = () => {
      if (!url) return;
      $("deepCheck").textContent = "Checking..."; $("deepCheck").disabled = true;
      chrome.runtime.sendMessage({ type: "DEEP_CHECK", url }, res => {
        renderFromResponse(res);
        $("deepCheck").textContent = "Deep Check"; $("deepCheck").disabled = false;
      });
    };

    if (url && t?.id != null) {
      chrome.runtime.sendMessage({ type: "GET_VERDICT", tabId: t.id }, res => {
        if (res?.verdict) renderFromResponse(res.verdict);
        else chrome.runtime.sendMessage({ type: "MANUAL_CHECK", url }, r => renderFromResponse(r));
      });
    }
  });

  // Trust this favicon as a brand
  $("trustFavicon").onclick = () => {
    const out = $("trustResult");
    out.className = "scanResult";
    const hash = CURRENT_VERDICT?.faviconHash;
    const host = CURRENT_VERDICT?.host;
    if (!hash || !host) {
      out.className = "scanResult warn";
      out.textContent = "No favicon detected on this page yet. Run Quick Check first.";
      return;
    }
    chrome.runtime.sendMessage({ type: "TRUST_FAVICON", hash, host }, res => {
      if (res?.ok) {
        out.className = "scanResult ok";
        out.textContent = `Saved. Future sites using this favicon outside "${res.apex}" will be flagged as impersonation.`;
      } else {
        out.className = "scanResult bad";
        out.textContent = "Failed: " + (res?.error || "unknown");
      }
    });
  };

  // Manual URL scan
  $("manualScan").onclick = () => {
    const v = $("manualUrl").value.trim();
    if (!v) return;
    manualScan(v);
  };
  $("manualUrl").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); $("manualScan").click(); }
  });

  // QR scan
  const qrDrop = $("qrDrop"), qrFile = $("qrFile");
  qrDrop.onclick = () => qrFile.click();
  qrFile.addEventListener("change", (e) => {
    const f = e.target.files?.[0]; if (f) handleQrFile(f);
    e.target.value = "";
  });
  ["dragenter", "dragover"].forEach(ev => qrDrop.addEventListener(ev, e => {
    e.preventDefault(); e.stopPropagation(); qrDrop.classList.add("dragover");
  }));
  ["dragleave", "drop"].forEach(ev => qrDrop.addEventListener(ev, e => {
    e.preventDefault(); e.stopPropagation(); qrDrop.classList.remove("dragover");
  }));
  qrDrop.addEventListener("drop", (e) => {
    const f = e.dataTransfer?.files?.[0]; if (f) handleQrFile(f);
  });

  // Recent history
  chrome.runtime.sendMessage({ type: "HISTORY_GET" }, res => {
    if (res?.history) renderHistory(res.history);
    else renderHistory([]);
  });
});
