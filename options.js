// options.js — settings + allowlist manager + history viewer + stats

const $ = (id) => document.getElementById(id);

const SETTINGS_DEFAULTS = {
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
};

async function loadSettings() {
  const d = await chrome.storage.sync.get(SETTINGS_DEFAULTS);
  $("online").checked = !!d.onlineDeepChecksEnabled;
  $("notif").checked = !!d.notificationsEnabled;
  $("credWarn").checked = !!d.credentialWarningsEnabled;
  $("dlScan").checked = !!d.downloadScanEnabled;
  $("dlAutoBlock").checked = !!d.downloadAutoBlockMalicious;
  $("dlDeep").checked = !!d.downloadDeepScanEnabled;
  $("vt").value = d.vtKey || "";
  $("us").value = d.urlscanKey || "";
  $("gsb").value = d.gsbKey || "";
  $("abuseIPDB").value = d.abuseIPDBKey || "";
}
async function saveSettings() {
  await chrome.storage.sync.set({
    onlineDeepChecksEnabled: $("online").checked,
    notificationsEnabled: $("notif").checked,
    credentialWarningsEnabled: $("credWarn").checked,
    downloadScanEnabled: $("dlScan").checked,
    downloadAutoBlockMalicious: $("dlAutoBlock").checked,
    downloadDeepScanEnabled: $("dlDeep").checked,
    vtKey: $("vt").value.trim(),
    urlscanKey: $("us").value.trim(),
    gsbKey: $("gsb").value.trim(),
    abuseIPDBKey: $("abuseIPDB").value.trim()
  });
  const ok = $("ok");
  ok.style.display = "inline";
  setTimeout(() => ok.style.display = "none", 1500);
}

// ---------- Allowlist ----------
async function getAllowlist() {
  const { allowlist = {} } = await chrome.storage.sync.get({ allowlist: {} });
  return allowlist;
}
async function setAllowlist(allowlist) {
  await chrome.storage.sync.set({ allowlist });
}
async function notifyAllowlistChanged(host) {
  try {
    const tabs = await chrome.tabs.query({});
    for (const t of tabs) {
      if (!t.id) continue;
      chrome.tabs.sendMessage(t.id, { type: "ALLOWLIST_UPDATED", host }).catch(() => {});
    }
  } catch {}
}
function renderAllowlist(allowlist, filter = "") {
  const hosts = Object.keys(allowlist).sort();
  const filtered = filter
    ? hosts.filter(h => h.toLowerCase().includes(filter.toLowerCase()))
    : hosts;
  $("allowCount").textContent = String(hosts.length);
  const wrap = $("allowList");
  if (!filtered.length) {
    wrap.classList.add("empty");
    wrap.innerHTML = filter ? "No matching hosts." : "No allowlisted sites yet.";
    return;
  }
  wrap.classList.remove("empty");
  wrap.innerHTML = filtered.map(h =>
    `<div class="item"><span class="host">${escapeHtml(h)}</span><button class="iconbtn" data-host="${escapeHtml(h)}">Remove</button></div>`
  ).join("");
  wrap.querySelectorAll(".iconbtn").forEach(btn => {
    btn.onclick = async () => {
      const host = btn.getAttribute("data-host");
      const list = await getAllowlist();
      delete list[host];
      await setAllowlist(list);
      await notifyAllowlistChanged(host);
      renderAllowlist(list, $("allowFilter").value);
    };
  });
}

// ---------- History / stats ----------
async function getHistory() {
  const { scanHistory = [] } = await chrome.storage.local.get({ scanHistory: [] });
  return scanHistory;
}
function fmtTime(ts) {
  try {
    const d = new Date(ts);
    return d.toLocaleString();
  } catch { return ""; }
}
function severityPill(sev) {
  const color = sev === "red" ? "#b00020" : sev === "yellow" ? "#b8860b" : "#1b7f3a";
  const label = sev === "red" ? "High" : sev === "yellow" ? "Suspicious" : "Safe";
  return `<span style="font-size:11px;font-weight:700;color:${color};border:1px solid ${color};padding:2px 6px;border-radius:999px">${label}</span>`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}
function datestamp() {
  const d = new Date();
  return `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,"0")}${String(d.getDate()).padStart(2,"0")}`;
}
function csvCell(v) {
  const s = String(v ?? "");
  // Wrap in quotes if the value contains commas, quotes, or newlines
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}
function renderStats(history) {
  const total = history.length;
  let safe = 0, susp = 0, red = 0;
  for (const h of history) {
    if (h.severity === "red") red++;
    else if (h.severity === "yellow") susp++;
    else safe++;
  }
  $("stTotal").textContent = total;
  $("stSafe").textContent = safe;
  $("stSusp").textContent = susp;
  $("stRed").textContent = red;
}
function renderHistory(history, filter = "") {
  $("histCount").textContent = String(history.length);
  const filtered = filter
    ? history.filter(h => (h.host || "").toLowerCase().includes(filter.toLowerCase())
                       || (h.url || "").toLowerCase().includes(filter.toLowerCase()))
    : history;
  const wrap = $("histList");
  if (!filtered.length) {
    wrap.classList.add("empty");
    wrap.innerHTML = filter ? "No matching entries." : "No scans yet.";
    return;
  }
  wrap.classList.remove("empty");
  wrap.innerHTML = filtered.slice(0, 100).map(h => {
    const reasons = (h.reasons || []).slice(0, 3).map(r => `<li>${escapeHtml(r)}</li>`).join("");
    const score = typeof h.score === "number" ? h.score.toFixed(2) : "—";
    const primary = h.download
      ? `${escapeHtml(h.filename || "download")} <span style="color:#666;font-weight:400">from ${escapeHtml(h.host || h.url || "")}</span>`
      : escapeHtml(h.host || h.url || "—");
    const tags = [
      h.download ? "download" : null,
      h.deep ? "deep" : null,
      h.manual ? "manual" : null,
      h.script ? "script" : null
    ].filter(Boolean).join(" · ");
    return `<div class="item" style="display:block;padding:10px 8px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
        <div style="min-width:0;flex:1">
          <div class="host" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${primary}</div>
          <div style="font-size:11px;color:#666">${fmtTime(h.ts)} · score ${score}${tags ? " · " + tags : ""}</div>
        </div>
        ${severityPill(h.severity)}
      </div>
      ${reasons ? `<ul class="reasonsList">${reasons}</ul>` : ""}
    </div>`;
  }).join("");
}

// ---------- Wiring ----------
document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();
  $("save").onclick = saveSettings;

  let allowlist = await getAllowlist();
  renderAllowlist(allowlist);
  $("allowFilter").addEventListener("input", () => renderAllowlist(allowlist, $("allowFilter").value));

  $("allowExport").onclick = () => {
    const blob = new Blob([JSON.stringify(allowlist, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "phishspectre-allowlist.json";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  $("allowImportBtn").onclick = () => $("allowImportFile").click();
  $("allowImportFile").addEventListener("change", async (e) => {
    const file = e.target.files?.[0]; if (!file) return;
    try {
      const text = await file.text();
      const incoming = JSON.parse(text);
      if (!incoming || typeof incoming !== "object") throw new Error("Invalid JSON");
      const merged = { ...allowlist };
      for (const k of Object.keys(incoming)) {
        if (typeof k === "string" && k.length < 256) merged[k] = true;
      }
      await setAllowlist(merged);
      allowlist = merged;
      renderAllowlist(allowlist, $("allowFilter").value);
    } catch (err) {
      alert("Import failed: " + err.message);
    }
    e.target.value = "";
  });
  $("allowClear").onclick = async () => {
    if (!confirm("Remove all allowlisted sites?")) return;
    const oldHosts = Object.keys(allowlist);
    await setAllowlist({});
    allowlist = {};
    renderAllowlist(allowlist);
    for (const h of oldHosts) notifyAllowlistChanged(h);
  };

  let history = await getHistory();
  renderStats(history);
  renderHistory(history);
  $("histFilter").addEventListener("input", () => renderHistory(history, $("histFilter").value));

  // Export JSON — full log array
  $("histExportJson").onclick = () => {
    const blob = new Blob([JSON.stringify(history, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishspectre-history-${datestamp()}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  // Export CSV — flat spreadsheet
  $("histExportCsv").onclick = () => {
    const rows = [
      ["timestamp", "host", "url", "severity", "score", "deep", "manual", "download", "filename", "sources", "reasons"]
    ];
    for (const h of history) {
      rows.push([
        h.ts ? new Date(h.ts).toISOString() : "",
        h.host || "",
        h.url || "",
        h.severity || "",
        typeof h.score === "number" ? h.score.toFixed(4) : "",
        h.deep ? "yes" : "no",
        h.manual ? "yes" : "no",
        h.download ? "yes" : "no",
        h.filename || "",
        (h.sources || []).join(" | "),
        (h.reasons || []).join(" | ")
      ]);
    }
    const csv = rows.map(r => r.map(csvCell).join(",")).join("\r\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishspectre-history-${datestamp()}.csv`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  $("histClear").onclick = async () => {
    if (!confirm("Clear all scan history?")) return;
    await chrome.storage.local.set({ scanHistory: [] });
    history = [];
    renderStats(history); renderHistory(history);
  };
});
