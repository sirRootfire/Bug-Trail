# BugTrail

A local-first browser extension for **authorized access-control security research**.
BugTrail captures observations, discovers resource identifiers, compares responses,
and organizes findings and reports.

**Version:** 0.3.1

> Use BugTrail only on applications you own or have explicit permission to test.
> Mass Assignment tests send real requests that can change server-side data. Use
> dedicated test accounts and review each request before approving it.

## Features

- **Traffic inspection:** request methods, URLs, status codes, timings, and redirects.
- **Endpoint grouping:** turn resource-specific paths into reusable templates.
- **Identifier discovery:** find observed identifiers in URL paths, query parameters,
  JSON, GraphQL variables, form bodies, and selected HTML attributes and links.
- **Test identities:** label observations by account and organize authorized test accounts.
- **Auto Review:** explicitly approved GET comparisons using observed identifiers only;
  no identifier guessing or enumeration, with a maximum of five comparisons per run.
- **Privilege Review:** compare the same endpoint across authenticated test sessions.
- **Mass Assignment Review:** approved POST, PUT, or PATCH tests, with an optional
  follow-up check for persistence.
- **Sensitive-data signals:** detect password fields, API keys, and token-like values.
- **Findings and reports:** track verification status and export Markdown or JSON.
- **Scope and audit controls:** configure allowed and excluded hosts and review action history.

## Browser versions

| | Chrome | Firefox |
|---|---|---|
| Source folder | `bugtrail-chrome/` | `bugtrail-firefox/` |
| Manifest version | 3 | 2 |
| Background execution | Module service worker | Module loaded by `background.html` |
| Enhanced redirect inspection | Optional `chrome.debugger` permission | Unavailable |

Both folders contain the same application code. Their manifests differ, and Firefox
has an additional background HTML entry point.

## Installation

Download the repository ZIP and extract it, or clone it:

```sh
git clone https://github.com/sirRootfire/Bug-Trail.git
```

No package installation or build step is required.

### Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the `bugtrail-chrome` folder.

### Firefox

1. Open `about:debugging`.
2. Select **This Firefox**.
3. Click **Load Temporary Add-on**.
4. Select `bugtrail-firefox/manifest.json`.

Firefox's temporary installation is removed when the browser restarts.

## Getting started

1. Open the extension popup and select **Workspace**.
2. In **Settings**, configure the authorized host under **Scope** and grant the
   requested host permission.
3. In **Identities**, add a test-account label and select the active capture identity.
4. Start capture, then reload and browse the target application.
5. Inspect **Traffic**, **Endpoints**, and **Identifiers**.
6. Preview a review action, check its target and account session, and explicitly approve it.
7. Validate any findings manually and export selected results from **Reports**.

## Project structure

The following files are shared by both browser folders:

| Path | Purpose |
|---|---|
| `manifest.json` | Browser configuration, entry points, and permissions |
| `popup.html`, `popup.js` | Quick capture controls and workspace access |
| `app.html`, `app.css`, `app.js` | Main workspace interface |
| `background.js` | Capture coordination, message handling, and review execution |
| `content-script.js` | DOM observations, page-hook relay, and approved review requests |
| `page-hook.js` | Best-effort inspection of the page's own same-origin fetch/XHR responses |
| `debugger-capture.js` | Optional Chrome redirect status/header inspection |
| `core/` | Scope, identifiers, relationships, response comparison, findings, and reports |
| `shared/ext.js` | Shared browser API access |
| `shared/store.js` | Extension-local state, retention, and audit storage |

The application uses JavaScript, HTML, CSS, and browser extension APIs without a
frontend framework or backend service.

## Privacy and limitations

- State is stored in the extension's `storage.local`; the project does not include
  cloud synchronization. Review requests still communicate with the target application.
- Secret detection and redaction are heuristic. Inspect reports before publishing or sharing them.
- Imported credential passwords are discarded rather than saved; importing accounts
  does not log in or automate authentication.
- Identity labels do not isolate sessions. Tabs in one browser profile normally share
  cookies, so opening two tabs does not automatically create two independent accounts.
- Passive response-body inspection is best-effort and limited to supported same-origin
  page fetch/XHR calls after hook injection. Not all network response bodies are available.
- Enhanced inspection in Chrome can recover a redirect's real status and `Location`
  header during approved reviews. It does not inspect the original redirect body.
- A successful status code or response difference is not proof of an authorization flaw.
  Findings marked **Potential** or **Needs Verification** require manual validation.
- Capture-log retention defaults to 14 days. Curated identifiers, identities, credentials,
  and findings are not automatically removed by that retention policy.
