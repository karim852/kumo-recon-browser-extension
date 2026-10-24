# Security policy

## Reporting

Open a private security advisory on this repository, or email the address on
the GitHub profile. Please do not open a public issue for a vulnerability in
the extension itself.

## What this extension does, in security terms

- It sends HTTP requests to a domain **you** choose, from **your** browser,
  with **your** IP. It is not a proxy and there is no backend.
- Every request is sent with `credentials: 'omit'`, so your cookies and
  sessions are never attached to a scan.
- No telemetry, no analytics, no remote code. Everything executes from files
  in the package.

## Reporting a false positive

False positives are treated as bugs. Open an issue with the module name, the
path, and what the finding claimed. A finding you cannot reproduce by hand is
a finding that should not have been reported.

## Responsible use

Only scan systems you own or have written authorisation to test. The one-click
convenience does not change what is legal where you are.
