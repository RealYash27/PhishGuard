// background.js — PhishSpectre service worker
// Heuristics + ML scoring + reputation providers (VirusTotal, PhishStats, urlscan.io,
// Google Safe Browsing v5) + RDAP domain-age + typosquatting detection.

let MODEL = null;

// ---------- Settings / storage ----------
async function getAllowlist() {
  const { allowlist = {} } = await chrome.storage.sync.get({ allowlist: {} });
  return allowlist;
}
async function isAllowlisted(url) {
  try {
    const host = new URL(url).hostname;
    const allowlist = await getAllowlist();
    return !!allowlist[host];
  } catch { return false; }
}
async function getSettings() {
  return await chrome.storage.sync.get({
    onlineDeepChecksEnabled: false,
    notificationsEnabled: true,
    credentialWarningsEnabled: true,
    downloadScanEnabled: false,
    downloadDeepScanEnabled: false,
    downloadAutoBlockMalicious: true,
    vtKey: "",
    urlscanKey: "",
    gsbKey: "",
    abuseIPDBKey: ""
  });
}

// ---------- Trusted brand favicons (chrome.storage.sync) ----------
// Map of { faviconSha256: registrableApex }. Populated from popup when the user
// marks the current page as a trusted brand. If a later page presents the same
// favicon hash but a different apex, it's flagged as impersonation.
const FAVICON_KEY = "trustedFavicons";
async function getTrustedFavicons() {
  const { [FAVICON_KEY]: m = {} } = await chrome.storage.sync.get({ [FAVICON_KEY]: {} });
  return m;
}
async function setTrustedFavicon(hash, apex) {
  const m = await getTrustedFavicons();
  m[hash] = apex;
  await chrome.storage.sync.set({ [FAVICON_KEY]: m });
  return m;
}
function apexOf(host) {
  const parts = String(host || "").toLowerCase().split(".");
  if (parts.length < 2) return host || "";
  return parts.slice(-2).join(".");
}
async function checkFaviconImpersonation(host, faviconHash) {
  if (!faviconHash) return null;
  const m = await getTrustedFavicons();
  const trustedApex = m[faviconHash];
  if (!trustedApex) return null;
  if (apexOf(host) === trustedApex) return null;
  return { brandApex: trustedApex, currentApex: apexOf(host) };
}

// ---------- History log (chrome.storage.local) ----------
const HISTORY_KEY = "scanHistory";
const HISTORY_MAX = 200;
async function appendHistory(entry) {
  try {
    const { [HISTORY_KEY]: list = [] } = await chrome.storage.local.get({ [HISTORY_KEY]: [] });
    list.unshift(entry);
    if (list.length > HISTORY_MAX) list.length = HISTORY_MAX;
    await chrome.storage.local.set({ [HISTORY_KEY]: list });
  } catch (e) { console.warn("history append failed", e); }
}

// ---------- Model ----------
async function loadModel() {
  if (MODEL) return MODEL;
  try {
    MODEL = await (await fetch(chrome.runtime.getURL("model/lr_model.json"))).json();
  } catch {
    MODEL = { features: [], weights: [], bias: 0, scaler: { mean: [], std: [] }, numeric_indices: [] };
  }
  return MODEL;
}

// ---------- URL features ----------
function shannonEntropy(s) {
  const f = {}; for (const c of s) f[c] = (f[c] || 0) + 1;
  const n = s.length || 1; let H = 0;
  for (const k in f) { const p = f[k] / n; H -= p * Math.log2(p); }
  return Math.min(1, H / 5);
}
function isIPv4(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(h); }
const RARE_TLDS = new Set([
  "top","xyz","online","club","support","live","shop","buzz","monster",
  "click","gq","cf","ml","tk","work","lol","quest","fit","rest","cyou"
]);

const URL_SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","ow.ly","short.link","rb.gy","cutt.ly",
  "is.gd","v.gd","tiny.cc","bl.ink","shorturl.at","clck.ru","lnkd.in",
  "buff.ly","adf.ly","goo.gl","t.ly","s.id","x.gd"
]);

function registrableApex(host) {
  const parts = String(host || "").toLowerCase().split(".");
  return parts.length >= 2 ? parts.slice(-2).join(".") : host;
}

const SUSP_PATH_RE = /\/(login|signin|sign-in|secure|verify|verification|account|update|confirm|banking|wallet|recover|reset|credential|auth|submit|2fa|mfa|otp|checkpoint|unlock|webscr)/i;
const SUSP_QUERY_RE = /[?&](redirect|return|next|url|continue|goto|dest|destination|token|auth|session|verify|reset)=/i;
const HYPHEN_RE = /(-{2,})|(-[^-]+-[^-]+-[^-]+-)/;

function computeUrlFeatures(raw) {
  let u; try { u = new URL(raw); } catch { return null; }
  const host = u.hostname, path = u.pathname || "";
  const dots = (host.match(/\./g) || []).length;
  const qn = Array.from(new URLSearchParams(u.search)).length;
  return {
    host_len: host.length, path_len: path.length, dots, qparams: qn,
    subdomain_depth: Math.max(0, host.split(".").length - 2),
    entropy: shannonEntropy(host.replace(/\./g, "")),
    has_at: raw.includes("@") ? 1 : 0,
    ip_host: isIPv4(host) ? 1 : 0,
    has_punycode: host.includes("xn--") ? 1 : 0,
    http_not_https: (u.protocol !== "https:") ? 1 : 0,
    tld_rare: RARE_TLDS.has((host.split(".").pop() || "").toLowerCase()),
    double_ext: /\.(exe|zip|rar|pdf|doc|docx|xls|xlsx|ppt|pptx)\.\w{2,6}$/i.test(path),
    is_shortener: URL_SHORTENERS.has(host) || URL_SHORTENERS.has(registrableApex(host)),
    susp_path: SUSP_PATH_RE.test(path + (u.search || "")),
    susp_query: SUSP_QUERY_RE.test(u.search || ""),
    excess_hyphens: HYPHEN_RE.test(host.split(".").slice(0, -1).join(".")),
    host, path, href: raw, protocol: u.protocol
  };
}

// ---------- Typosquatting (brand impersonation by name) ----------
const BRANDS = [
  "google","gmail","youtube","facebook","instagram","whatsapp","twitter","x",
  "amazon","apple","icloud","microsoft","outlook","office","live","linkedin",
  "paypal","netflix","spotify","github","dropbox","adobe","steam",
  "chase","wellsfargo","bankofamerica","citibank","hsbc","barclays",
  "sbi","hdfcbank","icicibank","axisbank","kotak","paytm","phonepe","gpay",
  "binance","coinbase","metamask","kraken","trustwallet"
];
function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  const dp = new Array(n + 1);
  for (let j = 0; j <= n; j++) dp[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = dp[0]; dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = a[i - 1] === b[j - 1] ? prev : 1 + Math.min(prev, dp[j], dp[j - 1]);
      prev = tmp;
    }
  }
  return dp[n];
}
function registrableLabel(host) {
  const parts = host.toLowerCase().split(".");
  if (parts.length < 2) return host;
  return parts[parts.length - 2];
}
const GLYPH_MAP = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "8": "b",
  "@": "a",
  "\u0456": "i",   // Cyrillic і
  "\u04CF": "l",   // Cyrillic ӏ
  "\u0430": "a",   // Cyrillic а
  "\u043E": "o",   // Cyrillic о
  "\u0440": "p",   // Cyrillic р
  "\u0435": "e",   // Cyrillic е
  "\u0441": "c",   // Cyrillic с
  "\u0445": "x",   // Cyrillic х
};
function normalizeGlyphs(s) {
  let r = String(s).toLowerCase()
    .replace(/vv/g, "w").replace(/rn/g, "m").replace(/cl/g, "d");
  return r.replace(/[013456@\u0456\u04CF\u0430\u043E\u0440\u0435\u0441\u0445]/g,
                   c => GLYPH_MAP[c] || c);
}
function typosquatCheck(host) {
  const label = registrableLabel(host);
  if (!label || label.length < 3) return null;
  if (BRANDS.includes(label)) return null;
  const normLabel = normalizeGlyphs(label);
  let best = null;
  for (const brand of BRANDS) {
    const d = levenshtein(normLabel, brand);
    if (d > 0 && d <= 2 && Math.abs(label.length - brand.length) <= 2) {
      if (!best || d < best.distance) best = { brand, distance: d, label };
    }
    // Brand appears as a prefix/suffix with junk attached, e.g. "paypal-secure"
    if (d > 2 && (label.includes(brand) && label !== brand && brand.length >= 5)) {
      if (!best) best = { brand, distance: 99, label, contains: true };
    }
  }
  return best;
}

// ---------- Heuristics ----------
function heuristicScore(f, dom, typo) {
  if (!f) return 0;
  let s = 0;
  if (f.double_ext) s += 0.30;
  if (f.is_shortener) s += 0.20;
  if (f.susp_path) s += 0.15;
  if (f.susp_query) s += 0.10;
  if (f.excess_hyphens) s += 0.20;
  if (f.has_punycode) s += 0.5;
  if (f.ip_host) s += 0.4;
  if (f.has_at) s += 0.3;
  if (f.host_len + f.path_len > 100) s += 0.2;
  if (f.dots > 3) s += 0.15;
  if (f.tld_rare) s += 0.1;
  if (f.entropy > 0.62) s += 0.15;
  if (dom?.hasPassword && f.http_not_https) s += 0.25;
  if (dom?.crossDomainForm) s += 0.25;
  if (typo) s += typo.contains ? 0.25 : 0.45;
  return Math.min(1, s);
}
function topReasons(f, dom, typo, ageInfo) {
  const R = [];
  if (f.double_ext) R.push("Double file extension (e.g. .pdf.exe) — almost certainly malware");
  if (f.is_shortener) R.push("URL shortener conceals real destination");
  if (f.susp_path) R.push("Suspicious path keyword (/login, /verify, /secure…)");
  if (f.susp_query) R.push("Suspicious redirect/token parameter in URL");
  if (f.excess_hyphens) R.push("Excessive hyphens in domain (common phishing pattern)");
  if (typo) {
    R.push(typo.contains
      ? `Hostname contains brand "${typo.brand}" — possible impersonation`
      : `Hostname looks similar to "${typo.brand}" (typosquatting)`);
  }
  if (f.has_punycode) R.push("Punycode / homoglyph domain");
  if (f.ip_host) R.push("IP address as host");
  if (f.has_at) R.push("'@' present in URL");
  if (f.host_len + f.path_len > 100) R.push("Very long URL");
  if (f.dots > 3) R.push("Deep subdomain chain");
  if (f.tld_rare) R.push("Rare/suspicious TLD");
  if (f.entropy > 0.62) R.push("High-entropy hostname");
  if (dom?.hasPassword && f.http_not_https) R.push("Password over HTTP (no HTTPS)");
  if (dom?.crossDomainForm) R.push("Form posts to a different domain");
  if (ageInfo?.ageDays != null && ageInfo.ageDays < 90) {
    R.push(`Newly registered domain (${ageInfo.ageDays} days old)`);
  }
  return R;
}
function scoreLR(feat, model) {
  if (!model?.features?.length || !model?.weights?.length) return 0.5;
  const num = new Set(model.numeric_indices || []), X = [];
  for (let i = 0; i < model.features.length; i++) {
    let v = feat[model.features[i]] ?? 0;
    if (num.has(i)) {
      const mu = model.scaler.mean[i] || 0, sd = model.scaler.std[i] || 1;
      v = (v - mu) / (sd || 1);
    }
    X.push(v);
  }
  let z = model.bias || 0;
  for (let i = 0; i < X.length; i++) z += (model.weights[i] || 0) * X[i];
  return Math.min(1, Math.max(0, 1 / (1 + Math.exp(-z))));
}
function fuseScores(h, m, dom) {
  let b = 0.6 * m + 0.4 * h;
  if (dom?.crossDomainForm) b += 0.25;
  if (dom?.hasPassword) b += 0.10;
  return Math.max(0, Math.min(1, b));
}
function severityFromScore(s, f, dom) {
  if (f?.double_ext) return "red";
  if (f?.has_punycode && dom?.crossDomainForm) return "red";
  if (s <= 0.40) return "green";
  if (s <= 0.80) return "yellow";
  return "red";
}

// ---------- URL canonicalization (for GSB) ----------
function canonicalize(u) {
  const url = new URL(u);
  url.hash = ""; url.username = ""; url.password = "";
  url.hostname = url.hostname.toLowerCase();
  if ((url.protocol === "http:" && url.port === "80") ||
      (url.protocol === "https:" && url.port === "443")) url.port = "";
  url.pathname = url.pathname.replace(/\/\/+/g, "/");
  return url;
}

// ---------- Network helpers ----------
const withTimeout = (p, ms = 4500) =>
  Promise.race([p, new Promise(r => setTimeout(() => r(null), ms))]);

function b64urlNoPadFromUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------- Provider: VirusTotal ----------
async function checkVirusTotal(u, key) {
  if (!key) return null;
  try {
    const id = b64urlNoPadFromUtf8(u);
    const r = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { "x-apikey": key }
    });
    if (r.status === 404) {
      const form = new URLSearchParams(); form.set("url", u);
      await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: { "x-apikey": key, "Content-Type": "application/x-www-form-urlencoded" },
        body: form.toString()
      });
      return { hit: false, submitted: true, reason: "Submitted to VirusTotal (pending analysis)" };
    }
    const json = await r.json();
    const stats = json?.data?.attributes?.last_analysis_stats || {};
    const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
    if (malicious > 0) return { hit: true, reason: `Flagged by VirusTotal (${malicious} vendors)`, meta: stats };
    return { hit: false, reason: "Not flagged by VirusTotal", meta: stats };
  } catch (e) { console.warn("VirusTotal error", e); return null; }
}

// ---------- Provider: PhishStats ----------
async function checkPhishStats(url) {
  try {
    const r = await fetch(
      `https://api.phishstats.info:443/api/phishing?_where=(url,eq,${encodeURIComponent(url)})`
    ).then(r => r.json());
    const hit = Array.isArray(r) && r.length > 0;
    return hit ? { hit: true, reason: "Found in PhishStats (reported phishing)", meta: r[0] } : { hit: false };
  } catch (e) { console.warn("PhishStats error", e); return null; }
}

// ---------- Provider: urlscan.io ----------
async function checkUrlscan(u, key) {
  if (!key) return null;
  try {
    const { hostname } = new URL(u);
    const r = await fetch(
      `https://urlscan.io/api/v1/search/?q=domain:${hostname}+AND+task.tags:phishing`,
      { headers: { "API-Key": key } }
    ).then(r => r.json());
    const hit = (r?.total || 0) > 0;
    return hit ? { hit: true, reason: "urlscan.io has phishing-tagged scans", meta: r } : { hit: false };
  } catch (e) { console.warn("urlscan error", e); return null; }
}

// ---------- Provider: Google Safe Browsing v5 (threatMatches) ----------
async function checkGSB(u, key) {
  if (!key) return null;
  try {
    const cu = canonicalize(u).href;
    const body = {
      client: { clientId: "phishspectre", clientVersion: "0.7.0" },
      threatInfo: {
        threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: cu }]
      }
    };
    const r = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    );
    if (!r.ok) return { hit: false, reason: `Safe Browsing error (${r.status})` };
    const json = await r.json();
    const matches = Array.isArray(json?.matches) ? json.matches : [];
    if (matches.length > 0) {
      const types = matches.map(m => m.threatType).join(", ");
      return { hit: true, reason: `Google Safe Browsing flagged: ${types}`, meta: matches };
    }
    return { hit: false, reason: "Not flagged by Google Safe Browsing" };
  } catch (e) { console.warn("GSB error", e); return null; }
}

// ---------- Provider: OpenPhish ----------
async function checkOpenPhish(url) {
  try {
    const now = Date.now();
    const { openphish_cache = null } = await chrome.storage.local.get("openphish_cache");
    let feed = null;
    if (openphish_cache && (now - openphish_cache.ts) < 3600000) {
      feed = openphish_cache.urls;
    } else {
      const r = await fetch("https://openphish.com/feed.txt", { cache: "no-store" });
      if (!r.ok) return null;
      const txt = await r.text();
      feed = txt.split("\n").map(l => l.trim()).filter(Boolean);
      await chrome.storage.local.set({ openphish_cache: { ts: now, urls: feed } });
    }
    const normalized = url.replace(/\/+$/, "").toLowerCase();
    const hit = feed.some(u => normalized.startsWith(u.toLowerCase().replace(/\/+$/, "")));
    return hit ? { hit: true, reason: "Found in OpenPhish live feed" } : { hit: false };
  } catch (e) { console.warn("OpenPhish error", e); return null; }
}

// ---------- Provider: AbuseIPDB ----------
async function checkAbuseIPDB(u, key) {
  if (!key) return null;
  try {
    const host = new URL(u).hostname;
    let ip = host;
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      const doh = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`
      ).then(r => r.json());
      const ans = doh?.Answer?.find(a => a.type === 1);
      if (!ans) return null;
      ip = ans.data;
    }
    const r = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { headers: { "Key": key, "Accept": "application/json" } }
    );
    if (!r.ok) return null;
    const j = await r.json();
    const score = j?.data?.abuseConfidenceScore ?? 0;
    if (score >= 50) return { hit: true, reason: `AbuseIPDB: ${score}% abuse confidence for ${ip}`, meta: j.data };
    if (score >= 20) return { hit: false, reason: `AbuseIPDB: low abuse score (${score}%) for ${ip}`, meta: j.data };
    return { hit: false };
  } catch (e) { console.warn("AbuseIPDB error", e); return null; }
}

// ---------- Domain age via RDAP ----------
async function checkDomainAge(host) {
  try {
    const labels = host.split(".");
    if (labels.length < 2) return null;
    const apex = labels.slice(-2).join(".");
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(apex)}`, {
      headers: { "accept": "application/rdap+json" }
    });
    if (!r.ok) return null;
    const j = await r.json();
    const events = Array.isArray(j?.events) ? j.events : [];
    const reg = events.find(e => e.eventAction === "registration");
    if (!reg?.eventDate) return null;
    const created = new Date(reg.eventDate);
    if (isNaN(created.getTime())) return null;
    const ageDays = Math.floor((Date.now() - created.getTime()) / 86400000);
    return { ageDays, created: reg.eventDate, apex };
  } catch (e) { console.warn("RDAP error", e); return null; }
}

// ---------- Deep Check ----------
async function deepCheck(url) {
  const s = await getSettings();
  if (!s.onlineDeepChecksEnabled) {
    return { delta: 0, reasonsAdd: ["Online Deep Check disabled"], sources: [] };
  }
  const [vt, ps, us, gsb, op, ab] = await Promise.all([
    withTimeout(checkVirusTotal(url, s.vtKey), 5000),
    withTimeout(checkPhishStats(url), 5000),
    withTimeout(checkUrlscan(url, s.urlscanKey), 5000),
    withTimeout(checkGSB(url, s.gsbKey), 5000),
    withTimeout(checkOpenPhish(url), 5000),
    withTimeout(checkAbuseIPDB(url, s.abuseIPDBKey), 5000),
  ]);
  let d = 0;
  const R = [];
  const S = [];
  if (gsb?.hit) { d += 0.55; R.push(gsb.reason); S.push("Google Safe Browsing"); }
  if (vt?.hit) { d += 0.45; R.push(vt.reason); S.push("VirusTotal"); }
  else if (vt?.submitted) { R.push(vt.reason); S.push("VirusTotal"); }
  if (op?.hit) { d += 0.35; R.push(op.reason); S.push("OpenPhish"); }
  if (ps?.hit) { d += 0.30; R.push(ps.reason); S.push("PhishStats"); }
  if (ab?.hit) { d += 0.25; R.push(ab.reason); S.push("AbuseIPDB"); }
  else if (ab?.reason) { R.push(ab.reason); }
  if (us?.hit) { d += 0.15; R.push(us.reason); S.push("urlscan.io"); }
  return { delta: Math.min(1, d), reasonsAdd: Array.from(new Set(R)), sources: S };
}

// ---------- Notifications ----------
async function maybeNotify(url, severity, reasons) {
  try {
    const s = await getSettings();
    if (!s.notificationsEnabled) return;
    if (severity !== "red") return;
    const host = new URL(url).hostname;
    chrome.notifications.create({
      type: "basic",
      iconUrl: chrome.runtime.getURL("assets/cyber.png"),
      title: "PhishSpectre — High risk",
      message: `${host}\n${(reasons || []).slice(0, 2).join(" · ")}`,
      priority: 2
    });
  } catch (e) { /* notifications API not available in some contexts */ }
}

// ---------- Verdict dispatch ----------
const LAST_VERDICT_BY_TAB = {};
function sendVerdict(tabId, score, sev, reasons, deep = false, sources = [], extras = {}) {
  const valid = Number.isInteger(tabId) && tabId >= 0;
  const payload = { type: "VERDICT", score, severity: sev, reasons, deep, sources, ...extras };
  if (valid) {
    LAST_VERDICT_BY_TAB[tabId] = payload;
    chrome.tabs.sendMessage(tabId, payload).catch(() => {});
    return;
  }
  chrome.tabs.query({ active: true, lastFocusedWindow: true }).then(tabs => {
    const id = tabs?.[0]?.id;
    if (Number.isInteger(id) && id >= 0) {
      LAST_VERDICT_BY_TAB[id] = payload;
      chrome.tabs.sendMessage(id, payload).catch(() => {});
    }
  }).catch(() => {});
}
chrome.tabs.onRemoved.addListener((tabId) => { delete LAST_VERDICT_BY_TAB[tabId]; });

async function setBadge(tabId, sev) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  try {
    const b = sev === "green" ? "" : (sev === "yellow" ? "!" : "⚠");
    await chrome.action.setBadgeText({ tabId, text: b });
    await chrome.action.setBadgeBackgroundColor({
      tabId,
      color: sev === "red" ? "#ff4d4f" : "#fadb14"
    });
  } catch {}
}

// ---------- Flows ----------
async function handleAutoCheck(tabId, url, dom, faviconHash = null) {
  if (await isAllowlisted(url)) {
    setBadge(tabId, "green");
    sendVerdict(tabId, 0, "green", ["Protection disabled for this site"], false, []);
    return { score: 0, severity: "green", reasons: ["Protection disabled for this site"], features: null };
  }

  const m = await loadModel();
  const f = computeUrlFeatures(url);
  const typo = f ? typosquatCheck(f.host) : null;
  const favImp = f ? await checkFaviconImpersonation(f.host, faviconHash) : null;

  let h = heuristicScore(f, dom, typo);
  if (favImp) h = Math.min(1, h + 0.5);

  const ml = scoreLR(f, m);
  let sc = fuseScores(h, ml, dom);
  if (favImp) sc = Math.min(1, sc + 0.2);

  const sev = favImp ? "red" : severityFromScore(sc, f, dom);
  const baseReasons = topReasons(f, dom, typo, null);
  const reasons = (favImp
    ? [`Favicon matches trusted brand "${favImp.brandApex}" but host is "${favImp.currentApex}" — possible impersonation`, ...baseReasons]
    : baseReasons
  ).slice(0, 5);

  setBadge(tabId, sev);
  sendVerdict(tabId, sc, sev, reasons, false, [], {
    typo, protocol: f?.protocol, host: f?.host, faviconHash, favImp
  });

  appendHistory({
    url, host: f?.host || "", score: sc, severity: sev,
    reasons, deep: false, sources: [], ts: Date.now()
  });
  if (sev === "red") maybeNotify(url, sev, reasons);

  return { score: sc, severity: sev, reasons, features: f, heur: h, ml, typo, faviconHash, favImp };
}

async function handleDeepCheck(tabId, url, dom, faviconHash = null) {
  if (await isAllowlisted(url)) {
    setBadge(tabId, "green");
    sendVerdict(tabId, 0, "green", ["Protection disabled for this site"], true, []);
    return { score: 0, severity: "green", reasons: ["Protection disabled for this site"], deep: true, sources: [] };
  }

  const base = await handleAutoCheck(tabId, url, dom, faviconHash);

  let host = ""; try { host = new URL(url).hostname; } catch {}
  const [extra, ageInfo] = await Promise.all([
    deepCheck(url),
    host ? withTimeout(checkDomainAge(host), 5000) : Promise.resolve(null)
  ]);

  let score = Math.min(1, base.score + (extra.delta || 0));
  if (ageInfo?.ageDays != null && ageInfo.ageDays < 90) score = Math.min(1, score + 0.15);
  const sev = severityFromScore(score, base.features, dom);

  const ageReasons = ageInfo?.ageDays != null && ageInfo.ageDays < 90
    ? [`Newly registered domain (${ageInfo.ageDays} days old)`] : [];
  const reasons = Array.from(new Set([...(base.reasons || []), ...ageReasons, ...((extra.reasonsAdd || []))])).slice(0, 8);

  setBadge(tabId, sev);
  sendVerdict(tabId, score, sev, reasons, true, extra.sources || [], {
    typo: base.typo, protocol: base.features?.protocol, host: base.features?.host, ageInfo
  });

  appendHistory({
    url, host: base.features?.host || "", score, severity: sev,
    reasons, deep: true, sources: extra.sources || [], ts: Date.now(),
    ageDays: ageInfo?.ageDays ?? null
  });
  if (sev === "red") maybeNotify(url, sev, reasons);

  return {
    score, severity: sev, reasons, deep: true,
    sources: extra.sources || [], ageInfo, typo: base.typo,
    protocol: base.features?.protocol, host: base.features?.host
  };
}

// ---------- Manual one-off scan (URL paste from popup) ----------
async function handleManualUrl(url) {
  const f = computeUrlFeatures(url);
  if (!f) return { error: "Invalid URL" };
  const m = await loadModel();
  const typo = typosquatCheck(f.host);
  const h = heuristicScore(f, null, typo);
  const ml = scoreLR(f, m);
  const sc = fuseScores(h, ml, null);
  const sev = severityFromScore(sc, f, null);
  const reasons = topReasons(f, null, typo, null).slice(0, 6);
  appendHistory({
    url, host: f.host, score: sc, severity: sev,
    reasons, deep: false, sources: [], ts: Date.now(), manual: true
  });
  return { score: sc, severity: sev, reasons, host: f.host, protocol: f.protocol, typo };
}

// ---------- Download interception ----------
// Pauses every started download, scans the source URL with heuristics + (if a
// VirusTotal key is configured) the VT URL endpoint, then prompts the user to
// allow or cancel via a desktop notification with action buttons.
//
// Optional "deep scan" path: re-fetch the file via service-worker `fetch()`
// and upload to VT /files for content analysis. Works for files <32 MB on
// public URLs (i.e. no auth/cookies/streaming).

const RISKY_EXT = new Set([
  "exe","scr","bat","cmd","com","pif","msi","msp","vbs","vbe","jse","ws","wsf",
  "wsh","ps1","reg","jar","apk","dmg","app","sh","run","hta","lnk","gadget","cpl"
]);
function fileExt(filename) {
  const m = String(filename || "").match(/\.([a-z0-9]+)$/i);
  return m ? m[1].toLowerCase() : "";
}
function basename(p) {
  const s = String(p || "").replace(/\\/g, "/");
  const idx = s.lastIndexOf("/");
  return idx >= 0 ? s.slice(idx + 1) : s;
}
function shortName(name, max = 60) {
  const s = String(name || "");
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

// notifId -> { downloadId, severity, decided }
const PENDING_DL = {};

async function checkVirusTotalFile(buf, key) {
  // Upload file content to VirusTotal and poll for analysis result.
  if (!key) return null;
  try {
    if (buf.byteLength > 32 * 1024 * 1024) {
      return { hit: false, reason: "File too large for VirusTotal direct upload (>32 MB)" };
    }
    const form = new FormData();
    form.append("file", new Blob([buf]), "upload.bin");
    const upload = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST",
      headers: { "x-apikey": key },
      body: form
    });
    if (!upload.ok) return { hit: false, reason: `VT upload error (${upload.status})` };
    const upJson = await upload.json();
    const analysisId = upJson?.data?.id;
    if (!analysisId) return { hit: false, reason: "VT upload returned no analysis id" };

    // Poll up to ~45s
    for (let i = 0; i < 9; i++) {
      await new Promise(r => setTimeout(r, 5000));
      const r = await fetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`, {
        headers: { "x-apikey": key }
      });
      if (!r.ok) continue;
      const j = await r.json();
      const status = j?.data?.attributes?.status;
      if (status !== "completed") continue;
      const stats = j?.data?.attributes?.stats || {};
      const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
      if (malicious > 0) return { hit: true, reason: `VT file scan: flagged by ${malicious} vendors`, meta: stats };
      return { hit: false, reason: "VT file scan: clean", meta: stats };
    }
    return { hit: false, reason: "VT file scan: still analyzing (timeout)" };
  } catch (e) {
    console.warn("VT file scan error", e);
    return null;
  }
}

async function scanDownloadFileContent(url, key) {
  // Re-fetch the URL and upload to VT. Best-effort.
  try {
    const r = await fetch(url, { credentials: "omit" });
    if (!r.ok) return { hit: false, reason: `Could not re-fetch for file scan (HTTP ${r.status})` };
    const buf = await r.arrayBuffer();
    if (buf.byteLength === 0) return { hit: false, reason: "Empty download" };
    return await checkVirusTotalFile(buf, key);
  } catch (e) {
    return { hit: false, reason: "File re-fetch failed: " + (e.message || e) };
  }
}

async function handleDownloadCreated(item) {
  const settings = await getSettings();
  if (!settings.downloadScanEnabled) return;

  // Ignore our own programmatic downloads (e.g. allowlist export blob:).
  const url = item.finalUrl || item.url || "";
  if (!/^https?:\/\//i.test(url)) return;
  if (item.state !== "in_progress") return;

  // Pause as fast as possible.
  try { await chrome.downloads.pause(item.id); } catch (e) { /* may already be done */ }

  // Heuristics on URL + filename.
  const features = computeUrlFeatures(url);
  const typo = features ? typosquatCheck(features.host) : null;
  const heur = features ? heuristicScore(features, null, typo) : 0;
  const filename = basename(item.filename || item.url || "");
  const ext = fileExt(filename);
  const riskyType = RISKY_EXT.has(ext);

  const reasons = [];
  if (typo) reasons.push(typo.contains
    ? `Source domain looks like brand "${typo.brand}" (impersonation)`
    : `Source domain similar to "${typo.brand}" (typosquatting)`);
  if (features?.has_punycode) reasons.push("Punycode source domain");
  if (features?.ip_host) reasons.push("Source URL uses IP address");
  if (features?.http_not_https) reasons.push("Download served over HTTP");
  if (riskyType) reasons.push(`Risky file type (.${ext})`);

  // VirusTotal URL scan (uses the same flow as Deep Check).
  let vt = null;
  if (settings.vtKey) {
    vt = await withTimeout(checkVirusTotal(url, settings.vtKey), 8000);
    if (vt?.hit) reasons.push(vt.reason);
  }

  // Optional deep file-content scan (slow path, opt-in).
  let fileVt = null;
  if (settings.downloadDeepScanEnabled && settings.vtKey) {
    fileVt = await withTimeout(scanDownloadFileContent(url, settings.vtKey), 60000);
    if (fileVt?.hit) reasons.push(fileVt.reason);
  }

  // Decide severity.
  let severity = "green";
  if (vt?.hit || fileVt?.hit) severity = "red";
  else if (heur >= 0.6 || (riskyType && heur >= 0.4)) severity = "red";
  else if (heur >= 0.4 || riskyType || (features?.http_not_https && /\.(exe|msi|apk|dmg)$/i.test(filename))) severity = "yellow";

  // Track in scan history.
  appendHistory({
    url, host: features?.host || "", score: heur, severity,
    reasons: reasons.slice(0, 6),
    deep: !!fileVt, sources: [
      ...(vt?.hit ? ["VirusTotal-URL"] : []),
      ...(fileVt?.hit ? ["VirusTotal-File"] : [])
    ],
    ts: Date.now(), download: true, filename, downloadId: item.id
  });

  // Auto-allow safe downloads silently.
  if (severity === "green") {
    try { await chrome.downloads.resume(item.id); } catch {}
    return;
  }

  // Auto-cancel reds if user opted in.
  if (severity === "red" && settings.downloadAutoBlockMalicious) {
    try { await chrome.downloads.cancel(item.id); } catch {}
    chrome.notifications.create({
      type: "basic",
      iconUrl: chrome.runtime.getURL("assets/cyber.png"),
      title: "PhishSpectre — Download blocked",
      message: `${shortName(filename)}\n${reasons.slice(0, 2).join(" · ") || "Flagged as malicious"}`,
      priority: 2
    });
    return;
  }

  // Otherwise: prompt user via notification with Allow/Cancel buttons.
  const notifId = `phishspectre-dl-${item.id}-${Date.now()}`;
  PENDING_DL[notifId] = { downloadId: item.id, severity, decided: false, filename, reasons: reasons.slice(0, 3) };
  const title = severity === "red" ? "⚠ Dangerous download paused" : "Suspicious download paused";
  chrome.notifications.create(notifId, {
    type: "basic",
    iconUrl: chrome.runtime.getURL("assets/cyber.png"),
    title,
    message: `${shortName(filename)}\n${reasons.slice(0, 3).join(" · ") || "Suspicious signals on the source URL"}`,
    priority: severity === "red" ? 2 : 1,
    buttons: [{ title: "Allow download" }, { title: "Cancel download" }],
    requireInteraction: true
  }, (id) => { /* notification id is the one we passed */ });
}

function resolveDownloadDecision(notifId, allow) {
  const pending = PENDING_DL[notifId];
  if (!pending || pending.decided) return;
  pending.decided = true;
  if (allow) {
    chrome.downloads.resume(pending.downloadId).catch(() => {});
  } else {
    chrome.downloads.cancel(pending.downloadId).catch(() => {});
  }
  delete PENDING_DL[notifId];
  chrome.notifications.clear(notifId);
}

try {
  chrome.downloads.onCreated.addListener((item) => {
    handleDownloadCreated(item).catch(e => console.warn("download scan error", e));
  });
  chrome.notifications.onButtonClicked.addListener((notifId, btnIndex) => {
    if (!notifId.startsWith("phishspectre-dl-")) return;
    resolveDownloadDecision(notifId, btnIndex === 0);
  });
  chrome.notifications.onClosed.addListener((notifId, byUser) => {
    if (!notifId.startsWith("phishspectre-dl-")) return;
    // If user dismissed without choosing, default to keeping the download paused.
    // We leave the notification entry around briefly so the popup can offer a manual decision.
    // Auto-cancel after a long delay to avoid leaking paused downloads.
    const pending = PENDING_DL[notifId];
    if (pending && !pending.decided && byUser) {
      setTimeout(() => {
        const stillPending = PENDING_DL[notifId];
        if (stillPending && !stillPending.decided) resolveDownloadDecision(notifId, false);
      }, 60000);
    }
  });
} catch (e) {
  console.warn("download listener registration failed (permission missing?)", e);
}

// ---------- Message router ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg.type === "PAGE_LOADED") {
        const id = sender.tab?.id; if (!id) return;
        const r = await handleAutoCheck(id, msg.url, msg.dom, msg.faviconHash); sendResponse(r);
      } else if (msg.type === "MANUAL_CHECK") {
        const r = await handleAutoCheck(sender.tab?.id, msg.url, msg.dom || null, msg.faviconHash || null); sendResponse(r);
      } else if (msg.type === "DEEP_CHECK") {
        const r = await handleDeepCheck(sender.tab?.id, msg.url, msg.dom || null, msg.faviconHash || null); sendResponse(r);
      } else if (msg.type === "MANUAL_URL_SCAN") {
        const r = await handleManualUrl(msg.url); sendResponse(r);
      } else if (msg.type === "SETTINGS_GET") {
        sendResponse(await getSettings());
      } else if (msg.type === "HISTORY_GET") {
        const { [HISTORY_KEY]: list = [] } = await chrome.storage.local.get({ [HISTORY_KEY]: [] });
        sendResponse({ history: list });
      } else if (msg.type === "HISTORY_CLEAR") {
        await chrome.storage.local.set({ [HISTORY_KEY]: [] });
        sendResponse({ ok: true });
      } else if (msg.type === "TRUST_FAVICON") {
        if (!msg.hash || !msg.host) { sendResponse({ error: "missing hash/host" }); return; }
        const apex = apexOf(msg.host);
        await setTrustedFavicon(msg.hash, apex);
        sendResponse({ ok: true, apex });
      } else if (msg.type === "TRUSTED_FAVICONS_GET") {
        sendResponse({ favicons: await getTrustedFavicons() });
      } else if (msg.type === "PENDING_DL_GET") {
        const entries = Object.entries(PENDING_DL)
          .filter(([, v]) => !v.decided)
          .map(([notifId, v]) => ({ notifId, downloadId: v.downloadId, severity: v.severity, filename: v.filename || "", reasons: v.reasons || [] }));
        sendResponse({ pending: entries });
      } else if (msg.type === "DOWNLOAD_DECIDE") {
        resolveDownloadDecision(msg.notifId, !!msg.allow);
        sendResponse({ ok: true });
      } else if (msg.type === "GET_VERDICT") {
        const id = Number.isInteger(msg.tabId) ? msg.tabId : sender.tab?.id;
        sendResponse({ verdict: id != null ? LAST_VERDICT_BY_TAB[id] || null : null });
      } else if (msg.type === "SCRIPT_THREAT") {
        const host = (() => { try { return new URL(msg.url).hostname; } catch { return ""; } })();
        appendHistory({
          url: msg.url, host, score: 0.5, severity: "yellow",
          reasons: msg.threats || [], deep: false, sources: ["script-scan"],
          ts: Date.now(), script: true
        });
        sendResponse({ ok: true });
      }
    } catch (e) {
      console.warn("message handler error", e);
      try { sendResponse({ error: String(e?.message || e) }); } catch {}
    }
  })();
  return true;
});
