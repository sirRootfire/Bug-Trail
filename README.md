<div align="center">
  <img src="assets/logo.png" alt="BugTrail Logo" width="100%">
  <p><strong>A local-first browser workspace for authorized access-control security research.</strong></p>
</div>

---

## Overview

Manual access-control testing breaks down at scale: observations scatter across DevTools, terminals, and screenshots; resource identifiers lose their provenance; and multi-account sessions blur together.

**BugTrail** bridges the gap between raw traffic interception and formal reporting directly inside the browser—requiring **no proxy setup, no external backend, and no cloud telemetry**. It passively captures in-scope observations, normalizes endpoint templates, traces identifier provenance, executes explicitly approved bounded comparisons, and exports secret-redacted evidence reports.

> **Authorization & Safety Warning:**  
> Use BugTrail **only** on applications you own or have explicit written permission to test.  
> Mass Assignment tests send real state-changing requests (`POST`, `PUT`, `PATCH`) that can modify server-side data. Always use dedicated test accounts (`isTestAccount`) and review each comparison plan before approving execution.

---

## Documentation

**[Open the file-by-file documentation index](docs/README.md)**

Every current project file has its own English Markdown guide explaining its purpose, main functions or configuration, connections to other files, and implementation limitations. The guide folders mirror the Chrome and Firefox source folders.

---

## Core Features

- **Passive Traffic Inspection:** Captures request methods, sanitized URLs, status codes, timings, headers, and redirect events within an allow-listed scope—without modifying passive traffic.
- **Endpoint Grouping & Normalization:** Collapses resource-specific paths into reusable templates (e.g., `/api/orders/{orderId}`).
- **Provenance-Backed Identifier Discovery:** Extracts observed identifiers from URL paths, query parameters, JSON bodies, GraphQL variables, form bodies, and selected HTML attributes and links—recording the exact discovery method, location, confidence, and provenance without guessing or enumeration.
- **Test Identities:** Labels observations by account role to organize multi-session testing workflows across authorized test accounts.
- **Bounded Auto Review:** Runs explicitly approved read-only `GET` comparisons using **observed identifiers only**—no identifier guessing or enumeration, capped at **5 comparisons per run** (10 runs per 30 minutes, 350 ms pacing, automatic stop on `429` or consecutive `5xx` responses).
- **Privilege Review:** Compares the same endpoint across authenticated test sessions (2 to 5 labeled participants) for horizontal and vertical access-control checks without substituting identifiers.
- **Mass Assignment Review:** Executes double-confirmed `POST`, `PUT`, or `PATCH` JSON tests restricted to explicitly marked test accounts (`isTestAccount`), with an optional follow-up `GET` check for persistence verification.
- **Semantic Diff & Sensitive-Data Signals:** Reduces response differences to meaningful field/value changes while detecting and masking password fields, API keys, cookies, and token-like values before display or export.
- **Findings & Redacted Reports:** Tracks verification lifecycle (`Potential`, `Needs Verification`, `Verified`, `False Positive`, `Accepted Risk`, `Fixed`) with reproduction steps and exports secret-redacted **Markdown** or **JSON** reports.
- **Fail-Closed Scope & Audit Controls:** Enforces strict host allow-lists and exclusions (excluded hosts override allowed hosts) and maintains a local audit trail of review actions.

---

## Browser Versions

Both folders contain the same shared application core (`JavaScript ES Modules`, `HTML`, `CSS`) with zero frontend frameworks, build steps, or backend services. Only their extension manifests and platform shells differ:

| Feature | Chrome | Firefox |
|---|---|---|
| **Source folder** | `bugtrail-chrome/` | `bugtrail-firefox/` |
| **Manifest version** | 3 | 2 |
| **Background execution** | Module service worker | Module loaded by `background.html` |
| **Enhanced redirect inspection** | Optional `chrome.debugger` permission | Unavailable |

---

## Installation

Download the repository ZIP and extract it, or clone it directly:

```sh
git clone https://github.com/sirRootfire/Bug-Trail.git
```

No package installation or build step is required.

### Google Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the `bugtrail-chrome` folder.

### Mozilla Firefox

1. Open `about:debugging`.
2. Select **This Firefox**.
3. Click **Load Temporary Add-on**.
4. Select `bugtrail-firefox/manifest.json`.

*(Note: Firefox's temporary installation is removed when the browser restarts.)*

---

## Getting Started

1. Open the extension popup and select **Workspace**.
2. In **Settings**, configure the authorized target host under **Scope** and grant the requested host permission.
3. In **Identities**, add a test-account label and select the active capture identity.
4. Click **Start Capture**, then reload and browse the target application normally.
5. Inspect captured observations across **Traffic**, **Endpoints**, and **Identifiers**.
6. Preview a bounded review action (**Auto Review**, **Privilege Review**, or **Mass Assignment**), verify its target and account session, and explicitly approve it.
7. Validate any **Potential** findings manually and export selected results from **Reports**.

---

## Project Structure

```text
Bug-Trail/
├── bugtrail-chrome/          # Chrome Manifest V3 build (includes debugger-capture.js)
├── bugtrail-firefox/         # Firefox Manifest V2 build (includes background.html)
└── docs/                     # File-by-file technical documentation index
```

### Key Shared Modules

| Path | Purpose |
|---|---|
| `manifest.json` | Browser configuration, entry points, and permissions |
| `popup.html`, `popup.js` | Quick capture controls and workspace access |
| `app.html`, `app.css`, `app.js` | Main local workspace interface |
| `background.js` | Capture coordination, message handling, scope enforcement, and review execution |
| `content-script.js` | DOM observations, page-hook relay, and approved same-origin review requests |
| `page-hook.js` | Best-effort inspection of the page's own same-origin `fetch`/`XHR` responses |
| `debugger-capture.js` | *(Chrome only)* Optional redirect status and `Location` header inspection |
| `core/` | Scope, identifiers, relationships, response comparison, semantic diffing, findings, and reports |
| `shared/ext.js` | Shared cross-browser WebExtension API access |
| `shared/store.js` | Extension-local state (`browser.storage.local`), retention policy, and audit storage |

---

## Privacy, Security & Limitations

- **Local-First Storage (`No Backend`):** State is stored locally in the extension's `browser.storage.local` (`bugtrail.v2`); the project includes no cloud synchronization, external server, or telemetry. Active review requests still communicate strictly with the in-scope target application.
- **Heuristic Secret Redaction:** Secret detection and redaction are heuristic. Always inspect exported reports before publishing or sharing them.
- **Credential Safety:** Imported credential passwords are discarded immediately rather than saved; importing accounts does not log in or automate authentication.
- **Session Isolation Model:** Identity labels organize test plans but do not isolate browser sessions. Tabs in one browser profile normally share cookies, so opening two tabs does not automatically create two independent accounts—use separate browser profiles or containers for concurrent multi-account testing.
- **Best-Effort Response Body Inspection:** Passive response-body inspection is best-effort and limited to supported same-origin page `fetch`/`XHR` calls after hook injection (capped at 64,000 bytes for request capture and 300,000 characters for page-hook responses). Binary responses and pre-hook traffic are recorded as metadata only.
- **Chrome Debugger Scope:** Enhanced inspection in Chrome can recover a redirect's real status and `Location` header during approved reviews; it does not inspect the original redirect body.
- **Manual Validation Required:** A `200 OK` status code or semantic response difference is not proof of an authorization flaw. Findings marked **Potential** or **Needs Verification** require manual ownership and business-impact validation.
- **Data Retention Policy:** Capture-log retention defaults to **14 days**. Curated identifiers, identities, credentials metadata, and findings are not automatically removed by that retention policy.
