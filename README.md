# AegisTrace — Phishing Attack Detector

**AegisTrace** is a full-stack cybersecurity web application built to inspect suspicious URLs, domains, TLS certificates, and email messages for phishing indicators in real time. Designed around a dark charcoal-grey and electric-blue visual language with live interactive particle dynamics, it pairs deterministic structural heuristics with live DNS, RDAP, SSL/TLS, and HTTP inspection to produce clear, explainable threat reports.

---

## Project Overview

Phishing attacks remain one of the most effective initial-access vectors against individuals and organizations. Modern campaigns combine disposable domains, automated free HTTPS certificates, Unicode homograph spoofing, URL shorteners, and deceptive email headers to bypass cursory visual checks.

AegisTrace provides an integrated inspection workbench where analysts and everyday users can:
1. Submit website URLs or suspicious links for multi-layer infrastructure and lexical inspection.
2. Paste raw email headers and message bodies (or load `.eml` / `.txt` files) to evaluate SPF/DKIM/DMARC alignment, display-name spoofing, social-engineering cues, and embedded links.
3. Track real, persisted scanning activity and threat analytics in a live cybersecurity dashboard without fabricated telemetry.

---

## Problem Statement

End-users and frontline defenders frequently rely on misleading trust cues—such as the browser padlock icon (`HTTPS`) or familiar brand names in subdomains—when deciding whether a link or email is safe. Conversely, purely opaque "black-box" risk scores fail to explain *why* a target was flagged or what limitations apply to automated inspection. There is a need for an accessible, transparent phishing detection tool that performs live technical verification while clearly communicating evidence, limitations, and remediation steps.

---

## Project Objectives

- **Multi-Layer URL & Domain Verification:** Combine lexical URL parsing, brand-typosquatting analysis, live DNS resolution (`A`/`AAAA`/`MX`/`SPF`/`DMARC`), RDAP domain-age lookup, X.509 TLS inspection, and SSRF-hardened HTTP redirect checking.
- **Email Threat Triage:** Parse mail headers (`From`, `Reply-To`, `Return-Path`, `Authentication-Results`), detect deceptive anchor-text mismatches, quantify urgency/credential-harvesting language, and automatically score extracted URLs.
- **Explainable Risk Scoring:** Classify targets transparently into **Safe** (`0–29%`), **Suspicious** (`30–59%`), or **Malicious** (`60–100%`) with per-signal point attribution and explicit caveats (including why HTTPS does not guarantee legitimacy).
- **Real-Time Telemetry:** Aggregate dashboard statistics strictly from actual user-executed scans stored persistently on the server.

---

## Features

- **Live Cybersecurity Dashboard:** Displays total scans, Safe/Suspicious/Malicious counts, interactive risk-score histogram, detection vector breakdown, and clickable recent scanning activity.
- **Dedicated URL & Link Scanner:** Four-stage animated inspection pipeline covering structure, DNS/RDAP, SSL/TLS certificates, and bounded HTTP behavior.
- **Email Phishing Analyzer:** Supports raw header + body paste and `.eml`/`.txt` upload, SPF/DKIM/DMARC evaluation, sender mismatch checks, risky attachment pattern detection, and one-click deep inspection of extracted URLs.
- **Detailed Security Reports:** Radial risk gauge, threat category, triggered signal breakdown with evidence, DNS & SSL telemetry panels, limitations disclosure, recommended actions, and JSON/Markdown report export.
- **Strict Grey & Blue Neon UI:** Charcoal-grey surfaces, electric-blue illumination, custom typography (`Outfit`, `Plus Jakarta Sans`, `JetBrains Mono`), and an interactive HTML5 canvas blue particle network.

---

## Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend Framework** | React 19 + TypeScript | Modular UI components and strict type safety |
| **Styling & Motion** | Tailwind CSS v4 + Motion | Responsive grey-and-blue styling and page transitions |
| **Icons & Visuals** | Lucide React + HTML5 Canvas | Crisp iconography and live interactive particle background |
| **Backend Server** | Express (Node.js 22 + `tsx`) | REST API routes, Vite dev middleware, static serving |
| **Network & Crypto** | Node `dns`, `tls`, `net`, `crypto` | Live DNS resolution, TLS certificate inspection, UUIDs |
| **Persistence** | Atomic JSON File Store (`.data/scans.json`) | Lightweight server-side scan history without external DB setup |

---

## System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                         Browser Client (React SPA)                      │
│  ParticleField · TopNav · Overview · URL Scanner · Email Analyzer       │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ HTTPS / JSON (/api/*)
┌───────────────────────────────▼─────────────────────────────────────────┐
│                       Express Server (server.ts)                        │
│  Input Validation · Security Headers · Body Size Caps · Vite Middleware │
├───────────────────────────────┬─────────────────────────────────────────┤
│   SSRF Guard (ssrf.ts)        │  Detection Engines                      │
│   - http/https only           │  - urlAnalyzer.ts (Lexical, Brand,      │
│   - Private/Loopback/Metadata │    DNS, RDAP, TLS, Safe HTTP Probe)     │
│     IP blocking               │  - emailAnalyzer.ts (Headers, Links,    │
│                               │    Social Engineering Cues)             │
├───────────────────────────────┴─────────────────────────────────────────┤
│               Atomic Scan Store (server/store/scanStore.ts)             │
│               Persists real reports & computes live stats               │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Detection Methodology

AegisTrace evaluates targets across seven signal categories and sums weighted evidence into a bounded `0–100` risk score:

1. **URL Structure:** Flags raw IP literals, `@` userinfo obfuscation, Punycode (`xn--`) / non-ASCII homograph labels, excessive subdomain nesting, high domain-label Shannon entropy, non-standard ports, URL shorteners, and clustered credential keywords.
2. **Brand Impersonation:** Normalizes common lookalike characters (`0→o`, `1→l`, `rn→m`, `vv→w`) and computes Levenshtein edit distance and subdomain/path inclusion against protected major brands.
3. **Domain & DNS Reputation:** Resolves live DNS `A`/`AAAA`/`MX`/`TXT` (`v=spf1`) and `_dmarc` records, flags high-abuse TLDs, and queries `rdap.org` to identify newly registered domains (`< 30` or `< 90` days).
4. **SSL & HTTPS Inspection:** Opens a live TLS socket to inspect certificate trust, hostname/SAN match, issuer organization, protocol version, and expiration—while explicitly warning that valid DV certificates do not prove site legitimacy.
5. **HTTP Behavior:** Performs an SSRF-checked, manual-redirect (`max 3 hops`), size-capped (`128 KB`) HTML inspection to detect cross-domain redirects, `<input type="password">` forms on flagged domains, and external `<form action>` exfiltration targets.
6. **Email Headers:** Parses `From`, `Reply-To`, `Return-Path`, and `Authentication-Results` (`spf`, `dkim`, `dmarc`) alongside display-name spoofing.
7. **Email Content:** Detects urgency coercion, credential/financial solicitation phrases, risky attachment filenames, and `<a href>` vs. visible link text mismatches.

**Classification Thresholds:**
- **0–29%:** `Safe` (No significant threat indicators observed)
- **30–59%:** `Suspicious` (Anomalous traits requiring manual verification)
- **60–100%:** `Malicious` (High-risk indicator cluster)

---

## Installation Instructions

1. **Clone or open the repository:**
   ```bash
   git clone <repository-url>
   cd aegistrace-phishing-detector
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

---

## Environment Setup

Copy `.env.example` if configuring custom environment variables:

```bash
cp .env.example .env
```

Available environment variables:
- `PORT`: Port for the Express server (defaults to `3000`).
- `NODE_ENV`: Set to `production` when serving the compiled `dist/` bundle.
- `APP_URL`: Optional hosted application URL.

No external paid threat-intelligence API keys are required for core detection functionality; DNS, TLS, and RDAP checks operate directly from the backend runtime.

---

## Execution Instructions

- **Development Mode (Express + Vite Middleware on Port 3000):**
  ```bash
  npm run dev
  ```

- **Type Checking:**
  ```bash
  npm run lint
  ```

- **Production Build & Start:**
  ```bash
  npm run build
  NODE_ENV=production npm start
  ```

---

## Project Folder Structure

```text
.
├── server.ts                          # Express entry point & API router
├── server/
│   ├── engine/
│   │   ├── urlAnalyzer.ts             # Lexical, DNS, RDAP, TLS & HTTP scanner
│   │   └── emailAnalyzer.ts           # Header, link & social-engineering engine
│   ├── security/
│   │   └── ssrf.ts                    # Private/loopback/metadata IP blocker
│   └── store/
│       └── scanStore.ts               # Atomic JSON persistence & stats aggregator
├── src/
│   ├── App.tsx                        # Main SPA shell & view transitions
│   ├── index.css                      # Tailwind v4 & grey/blue neon styling
│   ├── main.tsx                       # React root mount
│   ├── types/
│   │   └── scanner.ts                 # Shared TypeScript domain interfaces
│   └── components/
│       ├── ParticleField.tsx          # Interactive blue particle canvas
│       ├── TopNav.tsx                 # Three-zone top navigation bar
│       ├── DashboardOverview.tsx      # Live telemetry, charts & recent scans
│       ├── UrlScannerView.tsx         # URL input, live stages & results
│       ├── EmailAnalyzerView.tsx      # Email header/body & .eml analyzer
│       ├── DetectionReportView.tsx    # Detailed report, radial gauge & export
│       ├── ReportsArchiveView.tsx     # Searchable/filterable scan history
│       └── ClassificationMark.tsx     # Accessible grey-and-blue verdict mark
├── index.html                         # Fonts & metadata entry point
├── package.json
└── README.md
```

---

## Screenshots

> Add captured screenshots from your running instance (`http://localhost:3000`) into `docs/screenshots/` when publishing:
> - **Overview Dashboard:** Live KPI strip, risk distribution histogram, vector breakdown, and recent activity table.
> - **URL Scanner:** Four-stage animated blue neon scan progress and inline security report.
> - **Email Analyzer:** Header authentication audit, extracted link risk table, and deep-scan trigger.
> - **Security Report:** Radial risk score gauge, signal breakdown, DNS/SSL inspection panels, and export controls.

---

## Example Detection Workflow

1. Navigate to **URL Scanner** and submit `http://paypa1-secure-verify.xyz/login?session=8912a&update=billing`.
2. **Stage 1 (Lexical & Brand):** Detects `paypa1` homoglyph typosquatting against `paypal`, credential keywords (`login`, `verify`, `update`, `billing`), and elevated-risk `.xyz` TLD.
3. **Stage 2 & 3 (DNS / TLS):** Checks live DNS resolution and flags unencrypted `HTTP` transport.
4. **Result:** Classifies the URL as **Malicious**, displays the contributing signals with point weights, explains why the domain was flagged, and provides containment recommendations plus JSON/Markdown export.

---

## Security Considerations

- **SSRF Prevention:** `server/security/ssrf.ts` restricts protocols strictly to `http:` and `https:`, resolves target hostnames via DNS before connecting, and blocks loopback (`127.0.0.0/8`, `::1`), private RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud metadata (`169.254.0.0/16`, `fe80::/10`), and carrier-grade NAT ranges—re-validating every redirect hop.
- **No Blind HTTPS Trust:** The SSL/TLS inspector explicitly surfaces certificate issuer details and notes that free automated certificates are routinely abused by phishing sites.
- **Bounded Network Probes:** Outbound DNS, RDAP, TLS, and HTTP probes enforce strict timeouts (`2.5s–3.5s`) and cap HTTP HTML reads to `128 KB`.
- **Safe Output Rendering:** All inspected URLs, page titles, and email contents are rendered through React's safe text bindings without `dangerouslySetInnerHTML`.

---

## Future Enhancements

- Integration with community threat-intelligence feeds (e.g., OpenPhish, URLhaus, PhishTank) via optional server-side API keys.
- Screenshot and headless DOM rendering in an isolated sandbox container to detect visual brand cloning and QR-code phishing.
- Full RFC 5322 MIME multipart parser for inspecting nested `.eml` attachments and embedded HTML parts.
- Multi-user workspace authentication and team-shared blocklist export (STIX/TAXII or CSV).

---

## License

Licensed under the **Apache License 2.0**. See `SPDX-License-Identifier: Apache-2.0` headers in source files for details.
