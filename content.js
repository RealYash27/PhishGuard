// content.js — banner UI + form-submission interception
(function () {
  let LAST_VERDICT = null;
  let credWarnShown = false;
  // Synchronous cache so the form-submit handler can preventDefault without awaiting.
  let DISABLED_FOR_SITE = false;
  let CREDENTIAL_WARNINGS_ENABLED = true;

  async function refreshAllowlistFlag() {
    try {
      const { allowlist = {}, credentialWarningsEnabled = true } = await chrome.storage.sync.get({ allowlist: {}, credentialWarningsEnabled: true });
      DISABLED_FOR_SITE = !!allowlist[location.host];
      CREDENTIAL_WARNINGS_ENABLED = credentialWarningsEnabled;
    } catch { 
      DISABLED_FOR_SITE = false; 
      CREDENTIAL_WARNINGS_ENABLED = true;
    }
  }
  refreshAllowlistFlag();
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "sync" && (changes.allowlist || changes.credentialWarningsEnabled)) {
        refreshAllowlistFlag();
      }
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
    chrome.runtime.sendMessage({ type: "PAGE_LOADED", url: location.href, dom, faviconHash }, () => {
      void chrome.runtime.lastError; // suppress "receiving end does not exist" when SW is dormant
    });
  }

  const MINING_PATTERNS = [
    /coinhive\.min\.js/i, /cryptonight\.wasm/i, /miner\.start/i,
    /coinpot\.co/i, /webmr\.js/i, /deepminer/i, /crypto-loot/i,
    /minero\.cc/i, /jsecoin\.com/i, /coinimp\.com/i, /webmine\.cz/i,
  ];
  const SUSPICIOUS_PATTERNS = [
    { re: /eval\s*\(\s*atob\s*\(/, label: "Obfuscated eval(atob(...)) code" },
    { re: /document\.write\s*\(.*unescape/, label: "Suspicious document.write + unescape" },
    { re: /new\s+Function\s*\(\s*atob/, label: "Dynamic Function from base64" },
  ];

  function detectScriptThreats() {
    const threats = [];
    document.querySelectorAll("script").forEach(s => {
      const src = s.src || "";
      const code = s.textContent || "";
      MINING_PATTERNS.forEach(p => {
        if (p.test(src) || p.test(code)) threats.push("Crypto-mining script detected");
      });
      SUSPICIOUS_PATTERNS.forEach(({ re, label }) => {
        if (re.test(code)) threats.push(label);
      });
    });
    // Hidden 1x1 cross-origin iframes — tracking pixels / clickjacking.
    // CAREFUL: only flag iframes explicitly sized to ≤1px in BOTH dimensions
    // via inline style/attribute. Do NOT flag display:none or visibility:hidden,
    // because reCAPTCHA / OAuth / ad iframes legitimately use those.
    document.querySelectorAll("iframe").forEach(f => {
      try {
        const src = f.src || "";
        if (!src) return;
        if (new URL(src).host === location.host) return;
        const w = parseInt(f.style.width  || f.getAttribute("width")  || "999", 10);
        const h = parseInt(f.style.height || f.getAttribute("height") || "999", 10);
        if (!isNaN(w) && !isNaN(h) && w <= 1 && h <= 1) {
          threats.push("Hidden cross-origin iframe detected");
        }
      } catch {}
    });
    return [...new Set(threats)];
  }

  function anchorBelowInput(el, input) {
    const place = () => {
      const rect = input.getBoundingClientRect();
      el.style.top  = `${window.scrollY + rect.bottom + 6}px`;
      el.style.left = `${window.scrollX + rect.left}px`;
    };
    place();
    const onMove = () => place();
    window.addEventListener("scroll", onMove, { passive: true });
    window.addEventListener("resize", onMove);
    // Return a teardown function so callers can remove listeners on dismiss
    return () => {
      window.removeEventListener("scroll", onMove);
      window.removeEventListener("resize", onMove);
    };
  }

  function showSiteSuspiciousWarning(input) {
    if (isDisabledForSiteSync() || !CREDENTIAL_WARNINGS_ENABLED) return;
    if (!LAST_VERDICT || (LAST_VERDICT.severity !== "yellow" && LAST_VERDICT.severity !== "red")) return;
    if (credWarnShown) return;
    if (document.getElementById("__ps_cred_warn__")) return;

    const el = document.createElement('div');
    el.id = "__ps_cred_warn__";
    
    const isRed = LAST_VERDICT.severity === "red";
    const bg = isRed ? "#2b0000" : "#1c1c00";
    const border = isRed ? "#ff4d4f" : "#fadb14";
    const color = isRed ? "#ffd6d6" : "#fff8c4";
    const icon = isRed ? "🚨" : "⚠";
    const label = isRed ? "DANGEROUS" : "suspicious";

    el.style.cssText = [
      `position:absolute`, `z-index:2147483646`, `background:${bg}`,
      `border:1px solid ${border}`, `color:${color}`, `padding:10px 14px`,
      `border-radius:8px`, `max-width:280px`, `box-shadow:0 4px 16px rgba(0,0,0,.5)`,
      `font-family:Inter,system-ui,sans-serif`, `font-size:12px`, `line-height:1.4`
    ].join(';');

    const reasonsStr = (LAST_VERDICT.reasons || []).slice(0, 2).join(" · ");

    el.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px">
        <strong style="font-size:13px">${icon} PhishSpectre Warning</strong>
        <span class="ps-close-warn" style="cursor:pointer;opacity:0.7;padding-left:10px" title="Dismiss">✕</span>
      </div>
      <p style="margin:0">This site is flagged as <strong>${label}</strong>. Entering your password here may expose your credentials to attackers.</p>
      ${reasonsStr ? `<p style="margin:6px 0 0 0;font-size:11px;opacity:.8">Reasons: ${reasonsStr}</p>` : ''}
    `;

    document.body.appendChild(el);
    const teardown = anchorBelowInput(el, input);

    const dismiss = () => {
      credWarnShown = true;
      teardown();
      el.remove();
    };

    el.querySelector('.ps-close-warn').onclick = dismiss;
    setTimeout(() => { if (document.body.contains(el)) dismiss(); }, 6000);
  }

  // ---------- Weak / breached password detection ----------
  const WEAK_PASSWORDS = new Set([
    'password','password1','password123','123456','1234567','12345678',
    '123456789','1234567890','qwerty','qwerty123','qwertyuiop','abc123',
    'admin','admin123','admin1234','administrator','letmein','welcome',
    'monkey','dragon','master','sunshine','princess','football','shadow',
    'superman','michael','login','test','pass','default','iloveyou','hello',
    'charlie','111111','000000','pass123','root','toor','changeme','trustno1',
    'whatever','batman','starwars','freedom','mustang','access','baseball',
    'jessica','ninja','12345','1234','0000','11111111','passw0rd','p@ssword',
    'p@ss','p@ssw0rd','qazwsx','zaq1zaq1','1q2w3e4r','iloveyou1','secret',
    'solo','abcdef','abcd1234','pass1234','user','guest','temp','test123',
    'login123','welcome1','hello123','abc','aaaa','aaaaaa','asdfgh',
  ]);

  async function sha1Hex(str) {
    const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
  }

  async function hibpBreachCount(password) {
    try {
      const hash   = await sha1Hex(password);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);
      const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true' } // k-anonymity padding
      });
      if (!r.ok) return -1;
      const text = await r.text();
      for (const line of text.split('\r\n')) {
        const [s, c] = line.split(':');
        if (s === suffix) return parseInt(c, 10) || 1;
      }
      return 0; // not found in any breach
    } catch { return -1; } // -1 = network error, ignore silently
  }

  function showPwWarning(input, html, level) {
    if (!CREDENTIAL_WARNINGS_ENABLED) return;
    removePwWarning(input);
    const el = document.createElement('div');
    el.id = '__ps_pw_warn__';
    el.className = '__ps_pw_warn__';
    const bg     = level === 'danger' ? '#fff0f0' : '#fffbe6';
    const color  = level === 'danger' ? '#7b0012' : '#7d4e00';
    const border = level === 'danger' ? '#f5a0a0' : '#ffe58f';
    const icon   = level === 'danger' ? '🚨' : '⚠️';
    
    el.style.cssText = [
      `background:${bg}`, `color:${color}`, `border:1px solid ${border}`,
      'border-radius:6px', 'padding:6px 10px', 'max-width:320px',
      'font-size:12px', 'font-family:Inter,system-ui,Arial,sans-serif',
      'display:inline-flex', 'align-items:center', 'gap:8px', 'line-height:1.2',
      'position:absolute', 'z-index:2147483646', 'box-shadow:0 2px 8px rgba(0,0,0,0.1)'
    ].join(';');
    
    el.innerHTML = `<span style="font-size:15px;flex-shrink:0">${icon}</span>`
      + `<span style="flex:1">${html}</span>`
      + `<span class="ps-pw-warn-close" style="cursor:pointer;opacity:0.5;font-size:14px;flex-shrink:0" title="Dismiss">✕</span>`;
    
    document.body.appendChild(el);
    const teardown = anchorBelowInput(el, input);
    el.__psTeardown = teardown;

    const dismiss = () => removePwWarning(input);
    el.querySelector('.ps-pw-warn-close').onclick = dismiss;
    el.__psTimeout = setTimeout(() => {
      if (document.body.contains(el)) dismiss();
    }, 10000);
    
    // Interval check for input removed
    el.__psInterval = setInterval(() => {
      if (!document.body.contains(input)) dismiss();
    }, 500);
  }

  function removePwWarning(input) {
    const el = document.getElementById('__ps_pw_warn__');
    if (el) {
      if (el.__psTeardown) el.__psTeardown();
      if (el.__psTimeout) clearTimeout(el.__psTimeout);
      if (el.__psInterval) clearInterval(el.__psInterval);
      el.remove();
    }
  }

  async function checkPasswordField(input) {
    const val = input.value;
    if (!val || val.length < 3) { removePwWarning(input); return; }

    // HIBP k-anonymity breach check (only 5-char SHA-1 prefix sent — password stays private)
    const count = await hibpBreachCount(val);
    if (count > 0) {
      showPwWarning(input,
        `<strong>Breached password!</strong> This password has appeared in <strong>${count.toLocaleString()}</strong> data breach${count === 1 ? '' : 'es'}. Choose a different one.`,
        'danger');
    } else if (count === 0) {
      removePwWarning(input); // clean
    } else if (count === -1 && WEAK_PASSWORDS.has(val.toLowerCase())) {
      // Fallback: network error but it's a known weak password
      showPwWarning(input,
        `<strong>Weak password!</strong> This is one of the most commonly used passwords and will be guessed instantly.`,
        'danger');
    }
  }

  function attachPasswordWatcher(input) {
    if (input.__psWatched) return;
    input.__psWatched = true;
    let debounceTimer = null;

    input.addEventListener('focus', () => {
      showSiteSuspiciousWarning(input);
    });
    
    // Check as they type, but wait until they pause for 600ms (much faster UX than waiting for blur)
    input.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => checkPasswordField(input), 600);
    });
    
    // Also check on blur just in case they typed very fast and clicked away immediately
    input.addEventListener('blur', () => {
      clearTimeout(debounceTimer);
      checkPasswordField(input);
    });
  }

  function watchPasswordFields() {
    document.querySelectorAll('input[type="password"]').forEach(attachPasswordWatcher);
  }

  // Watch for dynamically injected password fields (SPAs)
  const _pwObserver = new MutationObserver(() => watchPasswordFields());
  _pwObserver.observe(document.body || document.documentElement, { childList: true, subtree: true });


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
      credWarnShown = false;
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
  watchPasswordFields(); // scan for password fields already in the DOM

  setTimeout(() => {
    if (isDisabledForSiteSync()) return;
    const threats = detectScriptThreats();
    if (threats.length > 0) {
      chrome.runtime.sendMessage({ type: "SCRIPT_THREAT", url: location.href, threats });
      // If no banner is currently rendered, show a yellow sub-banner with the threats.
      const root = document.getElementById("__phishspectre_banner__");
      if (!root || !root.innerHTML) {
        render("yellow", threats.map(t => `🔧 ${t}`), false, []);
      }
    }
  }, 800);
  const p = history.pushState, r = history.replaceState;
  const hook = fn => function () {
    const rv = fn.apply(this, arguments); setTimeout(notify, 200); return rv;
  };
  history.pushState = hook(p);
  history.replaceState = hook(r);
  addEventListener("popstate", () => setTimeout(notify, 200));
})();
