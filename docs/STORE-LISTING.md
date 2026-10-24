# Chrome Web Store submission — everything to paste

Screenshots are in this folder, already at 1280×800. Four is plenty; the
store shows up to five.

---

## Before you start

- A Google account you'll keep. **The developer email cannot be changed later.**
- The one-time registration fee, paid in the dashboard.
- A privacy policy at a public URL. There's a ready-to-publish one at the
  bottom of this file — put it in your repo and link to the raw page, or add
  it to your portfolio site.
- New publishers get **2 published extensions**; you can request more.

---

## The steps

1. **chrome.google.com/webstore/devconsole** → sign in → pay the fee once.
2. **Add new item** → **Choose file** → upload `kumo-extension.zip`.
   Zip the *contents* so `manifest.json` sits at the archive root — the same
   zip you load unpacked is fine.
3. Fill the four tabs below.
4. **Submit for Review**. Uncheck auto-publish if you want to release it
   yourself afterwards. A staged submission expires after **30 days**.

An automated install test runs as soon as you upload, so manifest problems
surface before a human sees it.

---

## Store listing tab

**Name**
```
Kumo 蜘蛛 — Domain Recon
```

**Summary** (132 char limit)
```
27 recon modules for the tab you're on — DNS, certificates, tech, exposed paths and 358 vulnerability checks. No server needed.
```

**Category:** Developer Tools
**Language:** English

**Description**
```
Kumo turns the tab you're on into a reconnaissance target and maps everything
reachable about the domain — in a panel, in a few seconds, with nothing to
install and no account to make.

Twenty-seven modules run in parallel and stream their results in as each one
lands:

• DNS records, SPF, DMARC and DKIM
• Certificates and subdomains from Certificate Transparency logs
• WHOIS / RDAP registration and expiry
• HTTP security headers, graded
• Technology fingerprinting and WAF detection
• Sensitive paths — 142 of them, checked against the site's own soft-404
• 358 vulnerability checks for known exposures
• Secrets left in JavaScript: API keys, tokens, database URLs
• Cloud buckets, API surface, GraphQL introspection
• Open ports and CVEs observed by Shodan InternetDB
• Breach and infostealer intelligence
• Google dorks and OSINT pivots, pre-built for the domain

EVERYTHING RUNS IN YOUR BROWSER

There is no backend. Kumo makes the requests itself and keeps the results in
the extension. Nothing is uploaded, nothing is logged, and there is no server
of mine for your scans to pass through.

Scans are also sent WITHOUT your cookies. Probing an admin path while you're
logged in would be a self-inflicted CSRF, so every request goes out with
credentials omitted.

BUILT FOR PEOPLE WHO DO THIS FOR A LIVING

• Scans keep running when you close the panel — reopen to find every result
• Findings ranked by severity; the loud cards open themselves
• Adjustable concurrency and request delay, so you can be gentle with a
  fragile target
• Export the raw JSON, or copy a one-line-per-module summary
• Four palettes, including a restrained one for client screenshots

Kumo asks for website access the first time you press Scan — not at install.

ONLY SCAN WHAT YOU'RE ALLOWED TO

This points 358 checks at whatever tab you have open. Use it on systems you
own or have written permission to test.

Open source, MIT licensed:
https://github.com/karim852/KUMO-Domain-Recon-Tool

A command-line version with live port scanning and full TLS inspection is in
the same repository.
```

---

## Privacy tab

**Single purpose**
```
Kumo performs security reconnaissance against a web domain the user chooses,
and displays the results. Every module serves that one purpose: gathering
publicly observable information about a domain and presenting it as a report.
```

**Permission justifications** — one per permission in your manifest:

| permission | paste this |
|---|---|
| `activeTab` | `Reads the hostname of the current tab so the scan target can be pre-filled. The user still has to press Scan; nothing runs automatically.` |
| `tabs` | `Reads the URL of the active tab to extract its hostname for the target field, and opens result links (OSINT pivots, Google dorks) in new tabs when the user clicks them.` |
| `storage` | `Stores the user's own settings — selected modules, colour theme, request concurrency — and the in-progress scan state, so results survive the popup being closed. All of it stays on the device.` |
| `cookies` | `Reads cookie security flags (Secure, HttpOnly, SameSite) for the scanned domain so the HTTP inspector can report on them. Set-Cookie is invisible to fetch(), so this is the only way. Cookie values are never read, stored or transmitted.` |
| `contextMenus` | `Adds "Scan this site" and "Scan this link's domain" to the right-click menu.` |
| `alarms` | `Keeps the service worker alive while a scan is running, so a long scan is not cut short when the popup closes.` |
| host access (optional) | `Kumo must send HTTP requests to the domain the user chooses to scan, and to the public data sources it queries (DNS-over-HTTPS resolvers, crt.sh, rdap.org, Shodan InternetDB, the Wayback Machine). The target is not known in advance, so the permission cannot be narrowed. It is requested when the user starts their first scan, not at install.` |

**Remote code:** select **No, I am not using remote code.**
Everything executes from files in the package; no `eval`, no remote scripts.

**Data usage** — tick these and nothing else:

| question | answer |
|---|---|
| Does it collect personally identifiable information? | **No** |
| Health / financial / authentication / personal communications / location? | **No** |
| Web history? | **No** — the current tab's hostname is read in-memory to pre-fill a field; it is never stored or sent anywhere. |
| User activity? | **No** |
| Website content? | **Yes** — Kumo fetches pages from the domain the user chooses to scan and analyses them locally. Nothing is transmitted off the device. |

Then certify all three: not sold to third parties, not used for unrelated
purposes, not used for creditworthiness.

> If any claim here stops being true — if you ever add analytics, crash
> reporting or a hosted component — the disclosures have to change with it.
> Mismatched disclosures are a common reason extensions get pulled.

---

## Distribution tab

- **Visibility:** start **Unlisted** if you'd rather not be discoverable
  while you shake out the first reviews. You can switch to Public later.
- **Regions:** all.
- **Pricing:** free.

---

## Test instructions tab

Reviewers won't know what to point it at, and a blank scan reads as broken.
Paste this:

```
No account or login is required.

1. Open any public website, for example https://example.com
2. Click the Kumo toolbar icon
3. The domain of the current tab appears in the box automatically
4. Click SCAN and accept the site-access prompt when it appears
5. Result cards stream in over roughly 5-20 seconds

Kumo needs site access to make the requests a scan is made of; it asks on
the first scan rather than at install, which is why the permission prompt
appears at step 4.

For a faster review pass, click the "modules" button and choose "quick" —
about a dozen modules that finish in a few seconds.

All processing is local. There is no backend service and no account system.
```

---

## Likely review friction, and what to say

**"Requests broad host permissions."** Expected for this category. The
justification above is the honest answer: the target is user-chosen and
unknowable in advance. It being *optional* and requested at first scan is
genuinely in your favour — say so.

**"Could be used maliciously."** The precedent is good: comparable recon
extensions are published. Your listing already says scan only what you're
authorised to, and the README repeats it. Don't bury that line.

**Rejection is not the end.** You get a reason, you fix it, you resubmit.
Most first-time rejections are a permission justification that didn't match
the manifest, or a privacy disclosure that contradicted the description.

---

## Privacy policy — publish this and link it

Save as `PRIVACY.md` in the repo, link the rendered GitHub page.

```markdown
# Privacy Policy — Kumo 蜘蛛 Browser Extension

Last updated: 2026-10-12

## The short version

Kumo collects nothing. There is no server, no account, no analytics, and no
telemetry. Nothing leaves your browser except the scan requests you ask for.

## What the extension stores

On your device only, via the browser's extension storage:

- your settings: selected modules, colour theme, request concurrency and delay
- the results of your most recent scan, so they survive closing the panel

This never leaves your browser. Removing the extension removes all of it.

## What the extension sends, and where

When you start a scan, Kumo makes requests to:

- the domain you chose to scan
- public data sources needed for that scan: DNS-over-HTTPS resolvers
  (Cloudflare, Google), crt.sh, rdap.org, ipwho.is, Shodan InternetDB,
  the Internet Archive, and Hudson Rock

These requests carry the domain you are scanning. They are sent without your
cookies, without a referrer, and without any identifier for you. They go to
those services directly; the author of this extension operates no server and
receives nothing.

Each of those services has its own privacy policy, which governs what it does
with a request it receives.

## What the extension reads

- The hostname of your active tab, to pre-fill the scan target. It is held in
  memory, is never stored, and is never transmitted.
- Cookie security flags (Secure, HttpOnly, SameSite) for a domain you scan,
  so the HTTP inspector can report on them. Cookie values are never read,
  stored or transmitted.

## What is never collected

No personal information, browsing history, credentials, analytics, crash
reports or usage statistics. Nothing is sold or shared, because nothing is
collected.

## Changes

Material changes will be published here and noted in the extension's store
listing.

## Contact

Issues: https://github.com/karim852/KUMO-Domain-Recon-Tool/issues
```
