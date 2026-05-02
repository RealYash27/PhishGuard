// content.js — banner UI + form-submission interception
(function () {
  let LAST_VERDICT = null;
  // Synchronous cache so the form-submit handler can preventDefault without awaiting.
  let DISABLED_FOR_SITE = false;

  async function refreshAllowlistFlag() {
    try {
      const { allowlist = {} } = await chrome.storage.sync.get({ allowlist: {} });
      DISABLED_FOR_SITE = !!allowlist[location.host];
    } catch { DISABLED_FOR_SITE = false; }
  }
  refreshAllowlistFlag();
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "sync" && changes.allowlist) refreshAllowlistFlag();
    });
  } catch {}

  function isDisabledForSiteSync() { return DISABLED_FOR_SITE; }

  function domSignals() {
    const hasPassword = !!document.querySelector('input[type="password"]');
    let crossDomainForm = false;
    try {
      for (const f of document.forms) {
        const a = new URL(f.getAttribute('action') || '', location.href);
        if (a.host && a.host !== location.host) { crossDomainForm = true; break; }
      }
    } catch {}
    return { hasPassword, crossDomainForm };
  }

  function findFaviconUrl() {
    const sels = ['link[rel~="icon"]', 'link[rel="shortcut icon"]', 'link[rel="apple-touch-icon"]'];
    for (const sel of sels) {
      const el = document.querySelector(sel);
      const href = el?.getAttribute('href');
      if (href) {
        try { return new URL(href, location.href).href; } catch {}
      }
    }
    try { return new URL('/favicon.ico', location.origin).href; } catch { return null; }
  }
  async function computeFaviconHash() {
    const url = findFaviconUrl();
    if (!url) return null;
    try {
      const res = await fetch(url, { credentials: 'omit', cache: 'force-cache' });
      if (!res.ok) return null;
      const buf = await res.arrayBuffer();
      if (buf.byteLength === 0 || buf.byteLength > 256 * 1024) return null;
      const hash = await crypto.subtle.digest('SHA-256', buf);
      return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch { return null; }
  }

  function ensureRoot() {
    let el = document.getElementById("__phishspectre_banner__");
    if (!el) {
      el = document.createElement("div");
      el.id = "__phishspectre_banner__";
      el.style.cssText = "position:fixed;left:0;right:0;top:0;z-index:2147483647;font-family:Inter,system-ui,Arial,sans-serif;";
      document.documentElement.appendChild(el);
    }
    return el;
  }

  function render(sev, reasons, deep = false, sources = []) {
    if (isDisabledForSiteSync()) { ensureRoot().innerHTML = ""; return; }
    const root = ensureRoot();
    if (sev === "green") { root.innerHTML = ""; return; }
    const color = sev === "red" ? "#2b0000" : "#1c1c00";
    const border = sev === "red" ? "#ff4d4f" : "#fadb14";
    const title = sev === "red"
      ? "Phishing warning"
      : (deep ? `Deep Check${sources.length ? ": " + sources.join(", ") : ": cautious"}` : "Caution: suspicious signals");
    const li = (reasons || []).map(r => `<li>${r}</li>`).join("");
    root.innerHTML = `
      <div style="background:${color};color:white;border-bottom:2px solid ${border};padding:10px 14px;display:flex;gap:12px;align-items:baseline;flex-wrap:wrap">
        <strong>${title}</strong>
        <ul style="margin:0;padding-left:18px;display:flex;gap:18px;list-style:disc;flex-wrap:wrap">${li}</ul>
        <div style="margin-left:auto;display:flex;gap:10px">
          ${sev !== "red" ? '<button id="ps-deep" style="background:#1677ff;border:none;color:white;padding:6px 10px;border-radius:6px;cursor:pointer">Deep check</button>' : ''}
          <button id="ps-dismiss" style="background:transparent;border:1px solid #aaa;color:#eee;padding:6px 10px;border-radius:6px;cursor:pointer">Dismiss</button>
        </div>
      </div>`;
    document.getElementById("ps-dismiss").onclick = () => { root.innerHTML = ""; };
    const btn = document.getElementById("ps-deep");
    if (btn) {
      btn.onclick = () => chrome.runtime.sendMessage(
        { type: "DEEP_CHECK", url: location.href, dom: domSignals() },
        res => render(res.severity, res.reasons, true, res.sources || [])
      );
    }
  }

  async function notify() {
    const dom = domSignals();
    const faviconHash = await computeFaviconHash();
    chrome.runtime.sendMessage({ type: "PAGE_LOADED", url: location.href, dom, faviconHash }, () => {});
  }

  // Form submission interception:
  //   - if banner shows red phishing warning, block submit entirely
  //   - if a form contains a password field AND the action posts to a different domain,
  //     show a confirm() prompt regardless of overall verdict
  //   - if a typosquatting hit is known, prompt before submitting passwords
  document.addEventListener("submit", e => {
    if (isDisabledForSiteSync()) return;

    const form = e.target;
    const root = document.getElementById("__phishspectre_banner__");
    const bannerIsRed = root && root.textContent.includes("Phishing warning");

    if (bannerIsRed) {
      e.preventDefault(); e.stopImmediatePropagation();
      alert("PhishSpectre: this page looks dangerous. Dismiss the banner if you really want to proceed (not recommended).");
      return;
    }

    let hasPassword = false;
    try { hasPassword = !!form.querySelector('input[type="password"]'); } catch {}
    if (!hasPassword) return;

    let actionHost = location.host;
    try {
      const a = new URL(form.getAttribute('action') || '', location.href);
      if (a.host) actionHost = a.host;
    } catch {}
    const crossDomain = actionHost !== location.host;

    if (crossDomain) {
      const ok = confirm(
        `PhishSpectre warning:\n\n` +
        `You are about to send a password from "${location.host}" to "${actionHost}".\n` +
        `Cross-domain credential submission is a common phishing pattern.\n\n` +
        `Continue submitting?`
      );
      if (!ok) { e.preventDefault(); e.stopImmediatePropagation(); return; }
    }

    if (LAST_VERDICT?.typo) {
      const t = LAST_VERDICT.typo;
      const msg = t.contains
        ? `Hostname "${location.host}" contains the brand name "${t.brand}" but is not the official site. This is a common impersonation pattern.`
        : `Hostname "${location.host}" is suspiciously similar to "${t.brand}". This may be a typosquatting attack.`;
      const ok = confirm(`PhishSpectre warning:\n\n${msg}\n\nSubmit password anyway?`);
      if (!ok) { e.preventDefault(); e.stopImmediatePropagation(); }
    }
  }, true);

  chrome.runtime.onMessage.addListener(msg => {
    if (msg.type === "VERDICT") {
      LAST_VERDICT = msg;
      render(msg.severity, msg.reasons, !!msg.deep, msg.sources || []);
    }
    if (msg.type === "ALLOWLIST_UPDATED") {
      try {
        if (msg.host === location.host) {
          const r = document.getElementById("__phishspectre_banner__");
          if (r) r.innerHTML = "";
        }
      } catch {}
    }
  });

  notify();
  const p = history.pushState, r = history.replaceState;
  const hook = fn => function () {
    const rv = fn.apply(this, arguments); setTimeout(notify, 200); return rv;
  };
  history.pushState = hook(p);
  history.replaceState = hook(r);
  addEventListener("popstate", () => setTimeout(notify, 200));
})();
