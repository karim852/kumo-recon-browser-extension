# Publishing checklist

## 1. Push to GitHub

Create an empty repo named `kumo-browser-extension` on github.com (no README,
no licence, no gitignore), then from this folder:

```bash
git remote add origin https://github.com/karim852/kumo-recon-browser-extension.git
git branch -M main
git push -u origin main
git tag v1.0.0
git push origin v1.0.0
```

Pushing the tag makes the CI build both packages and attach them to a
GitHub release automatically.

Then on the repo page: add the topics `security`, `osint`, `recon`,
`pentesting`, `browser-extension`, `chrome-extension`, `firefox-addon`, and
link it from the CLI repo's README so the two feed each other.

## 2. Firefox (free, live in minutes)

addons.mozilla.org → Developer Hub → **Submit a New Add-on** → *On this site*
→ upload `dist/kumo-firefox-1.0.0.zip`.

Listed add-ons go live immediately and are reviewed afterwards, so this is
the cheapest place to find real-world bugs.

Listing text: `docs/STORE-LISTING.md`.

## 3. Chrome ($5 once, covers Brave, Edge, Opera, Vivaldi)

chrome.google.com/webstore/devconsole → pay the one-time fee → **Add new
item** → upload `dist/kumo-chrome-1.0.0.zip`.

Fill four tabs. Everything to paste is in `docs/STORE-LISTING.md`, including
permission justifications and the privacy disclosures.

**One change since that file was written:** host access is now a *required*
permission, not an optional one. In the Privacy tab, justify
`host_permissions` with:

> Kumo sends HTTP requests to the domain the user chooses to scan, and to the
> public data sources it queries (DNS-over-HTTPS resolvers, crt.sh, the IANA
> RDAP registry, Shodan InternetDB, the Internet Archive). The target is not
> known in advance, so the permission cannot be narrowed to specific hosts.
> No request carries user credentials: every fetch is made with
> `credentials: 'omit'`.

## 4. Edge (free, optional)

partner.microsoft.com/dashboard/microsoftedge → upload the **Chrome** zip
unchanged. Edge accepts Chrome packages as they are.

## Before every submission

```bash
./build.sh
npx web-ext lint --source-dir=build/firefox     # must be 0 errors
python3 test/fixture_site.py                     # then scan testtarget.local
```

Expected against the fixture: 5 exposed paths, 4 vulnerability hits, 7
redacted secrets. Anything more is a false positive that regressed.
