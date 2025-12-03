# 🛡️ PhishGuard — Browser Phishing & URL Risk Detector

PhishGuard is a Chrome extension that helps you **identify phishing and suspicious websites** while you browse. It uses **URL heuristics + risk scoring** and can optionally run **reputation checks** (VirusTotal / PhishStats / urlscan.io) to give you a quick, understandable verdict.

---

## ✨ Features

- **Real-time detection** on page load
- **Risk verdicts**: Low / Suspicious / High
- **Warning banner** for risky pages
- **Site Report popup** with:
  - risk score + reasons
  - provider results (optional)
  - host + basic network info
- **Deep Check** (optional online reputation lookup)
- **Per-site allowlist** (“Disable protection for this site”)

---

## 🧠 How It Works (High Level)

PhishGuard evaluates the current URL using signals like:

- suspicious domain patterns (many subdomains, too long, high-entropy)
- punycode / homoglyph indicators (`xn--`)
- IP-based URLs
- suspicious characters (`@`)
- risky TLDs (configurable list)
- page indicators (e.g., presence of password fields)

If enabled, it can also query online services for known malicious URLs.

---

## 📦 Install (Load Unpacked)

1. Clone this repository or download as ZIP and extract it.
2. Open Chrome and go to: `chrome://extensions`
3. Enable **Developer mode** (top-right)
4. Click **Load unpacked**
5. Select the project folder that contains `manifest.json`

✅ PhishGuard should now appear in your extensions toolbar.

---

## ⚙️ Configuration

Open the extension **Options/Settings** page to configure:

- Enable/disable protection
- Enable online checks (Deep Check)
- Add API keys (optional, depending on provider)

### API Keys (Optional)

Some reputation providers require keys:

- **VirusTotal** → API key required for lookups
- **urlscan.io** → optional but recommended for better rate limits
- **PhishStats** → typically works without a key

> Keep keys private. Do not commit them to GitHub.

---

## 🧪 Usage

- Browse normally — PhishGuard runs automatically.
- Click the **PhishGuard icon** to view the **Site Report**:
  - Verdict + score
  - Reasons and detected indicators
  - Run **Quick Check** or **Deep Check**
- If a site is trusted, toggle:
  - **Disable protection for this site** (allowlist)

---

## 🔐 Privacy

- PhishGuard does **not** read or store your passwords or form inputs.
- If **Deep Check** is enabled, the extension may send the **URL/domain** to selected reputation services to determine if it is malicious.

---

## 🗂️ Project Structure

- `manifest.json` — extension config
- `background.js` — service worker/background logic
- `content.js` — page-level detection + warning UI
- `popup.html` / `popup.js` — toolbar popup UI
- `options.html` / `options.js` — settings page

---

## 🚧 Disclaimer

PhishGuard provides **risk indicators**, not a guarantee. Always verify:
- the domain spelling
- HTTPS certificate details
- suspicious login prompts / urgency language


## 🤝 Contributing

PRs are welcome!

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-change`
3. Commit your changes: `git commit -m "Add: my change"`
4. Push to your branch: `git push origin feature/my-change`
5. Open a Pull Request

---
