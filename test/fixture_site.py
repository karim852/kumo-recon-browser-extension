#!/usr/bin/env python3
"""A deliberately leaky website, used to prove the engine's matchers fire.

Serves the exact conditions the rules look for: an exposed .git/config and
.env, a Swagger spec, a GraphQL endpoint with introspection on, a JS bundle
full of planted credentials, a robots.txt pointing at sensitive paths, and a
response header set that should grade badly.
"""
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = b"""<!doctype html><html><head>
<meta charset="utf-8"><title>Acme Internal Portal</title>
<meta name="description" content="Staff tooling for Acme Corp.">
<meta name="generator" content="WordPress 6.4.2">
<link rel="icon" href="/favicon.ico">
<script src="/static/app.js"></script>
<script src="/static/vendor.js"></script>
<script>window.__CFG={endpoint:"/api/v2/accounts",host:"ldap.corp.internal"};</script>
</head><body>
<div id="root">wp-content/themes/acme</div>
<a href="mailto:soc@testtarget.local">security</a>
<p>jQuery 3.6.0 and React 18.2.0 power this page.</p>
</body></html>"""

# GitHub's push protection scans this file, and a literal "sk_live_..." in it
# looks exactly like a real leaked key, which blocks the push. So the fixture
# assembles its fake credentials at runtime: no secret-shaped literal is ever
# stored here, while the page it serves still carries full, realistic ones for
# the scanner under test to find.
def _j(*parts):
    return "".join(parts)


_FAKE = {
    "aws": _j("AKIA", "IOSFODNN7", "EXAMPLE"),
    "stripe": _j("sk", "_", "live", "_", "abcdefghijklmnopqrstuvwx"),
    "github": _j("ghp", "_", "abcdefghijklmnopqrstuvwxyz0123456789"),
    "gmaps": _j("AIza", "SyD-1234567890abcdefghijklmnopqrstu"),
    "slack": _j("https://hooks.", "slack.com/services/", "T000/B000/XXXXXXXXXXXX"),
    "mongo": _j("mongodb", "+srv://", "admin:s3cr3tpw@", "cluster0.mongodb.net/prod"),
    "password": _j("hunter2", "hunter2"),
}

APPJS = ("""
const AWS_KEY = "%(aws)s";
const stripe = "%(stripe)s";
const gh = "%(github)s";
const gmap = "%(gmaps)s";
const hook = "%(slack)s";
const db = "%(mongo)s";
const password = "%(password)s";
fetch("/api/v2/transfers"); fetch("/api/internal/admin");
const INTERNAL = "https://jenkins.corp.internal:8080/job/build";
""" % _FAKE).encode()

VENDORJS = b"var x=1;// nothing interesting here\n"

ROBOTS = b"""User-agent: *
Disallow: /wp-admin/
Disallow: /backup/
Disallow: /internal/api/
Disallow: /tmp/
Allow: /wp-admin/admin-ajax.php
Sitemap: https://testtarget.local/sitemap.xml
"""

GITCONFIG = b"""[core]
\trepositoryformatversion = 0
\tfilemode = true
[remote "origin"]
\turl = git@github.com:acme/portal.git
"""

ENVFILE = b"""APP_ENV=production
APP_KEY=base64:aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789==
DB_PASSWORD=sup3rs3cret
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

SWAGGER = json.dumps({
    "openapi": "3.0.0",
    "info": {"title": "Acme API", "version": "2.0"},
    "paths": {"/accounts": {"get": {}}, "/transfers": {"post": {}}},
}).encode()

FAVICON = bytes([0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10]) + bytes(range(256)) * 4

ROUTES = {
    "/": (200, "text/html", HOME),
    "/static/app.js": (200, "application/javascript", APPJS),
    "/static/vendor.js": (200, "application/javascript", VENDORJS),
    "/robots.txt": (200, "text/plain", ROBOTS),
    "/sitemap.xml": (200, "application/xml", b"<urlset></urlset>"),
    "/.git/config": (200, "text/plain", GITCONFIG),
    "/.git/HEAD": (200, "text/plain", b"ref: refs/heads/main\n"),
    "/.env": (200, "text/plain", ENVFILE),
    "/swagger.json": (200, "application/json", SWAGGER),
    "/favicon.ico": (200, "image/x-icon", FAVICON),
    "/.well-known/security.txt": (200, "text/plain", b"Contact: mailto:soc@testtarget.local\n"),
    "/server-status": (200, "text/html", b"<html><h1>Apache Server Status</h1><tr><td>Server Version</td></html>"),
    "/.DS_Store": (200, "application/octet-stream", b"\x00\x00\x00\x01Bud1" + bytes(200)),
}

NOT_FOUND = b"<html><head><title>404 Not Found</title></head><body>Page not found</body></html>"


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # deliberately weak header posture + version disclosure
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("X-Powered-By", "PHP/8.2.4")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "session=abc123; Path=/, tracker=xyz; Path=/; Secure")
        self.send_header("Access-Control-Allow-Origin", "*")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ROUTES:
            code, ctype, body = ROUTES[path]
            return self._send(code, ctype, body)
        return self._send(404, "text/html", NOT_FOUND)

    do_HEAD = do_GET

    def do_OPTIONS(self):
        self._send(200, "text/plain", b"", {"Allow": "GET, HEAD, POST, OPTIONS, TRACE"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        if self.path.split("?")[0] in ("/graphql", "/api/graphql"):
            if b"__schema" in body:
                return self._send(200, "application/json",
                                  json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}).encode())
        return self._send(404, "text/html", NOT_FOUND)


if __name__ == "__main__":
    import ssl, os
    here = os.path.dirname(os.path.abspath(__file__))
    srv = ThreadingHTTPServer(("127.0.0.1", 8732), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(here, "cert.pem"), os.path.join(here, "key.pem"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("fixture site on https://127.0.0.1:8732")
    srv.serve_forever()
