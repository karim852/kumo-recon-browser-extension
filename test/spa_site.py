#!/usr/bin/env python3
"""A single-page app that answers 200 with the same shell for every URL.

This is the shape that generates false positives: nothing is exposed, but
every rule path returns 200, and the shell contains common words that the
status+word rules match on. A correct scanner finds ZERO here.
"""
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SHELL = b"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><title>Acme Cloud Console</title>
<link rel="stylesheet" href="/assets/app.css">
</head><body>
<div id="root"></div>
<noscript>You need JavaScript to run this app.</noscript>
<script>
  // words that appear in plenty of vulnerability rule matchers
  window.__APP__ = {
    env: "production", config: {debug:false}, version: "4.2.1",
    database: "connected", admin: "/admin", login: "/login",
    error: null, status: "ok", server: "nginx", index: 0,
    phpinfo: false, swagger: "/docs", graphql: "/api", backup: null,
    repositoryformatversion: 0, core: true, ref: "refs/heads/main"
  };
</script>
<script src="/assets/app.js"></script>
</body></html>"""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        # every single path: 200 with the shell, like a client-routed SPA
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(SHELL)))
        self.send_header("Server", "nginx")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(SHELL)

    do_HEAD = do_GET

    def do_POST(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.do_GET()


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    srv = ThreadingHTTPServer(("127.0.0.1", 8734), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(here, "cert.pem"), os.path.join(here, "key.pem"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("SPA fixture on https://127.0.0.1:8734 (everything returns 200)")
    srv.serve_forever()
