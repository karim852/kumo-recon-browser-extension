"""
Generate rule-evaluation cases with engine.py's own verdicts, so the browser
matcher can be checked against the tool it mirrors across the whole playbook.

For every rule it builds:
  * a POSITIVE response synthesised from that rule's own matchers, so the rule
    ought to fire, and
  * the benign shapes that cause false positives in the field -- an SPA shell,
    a soft 404, a catch-all that echoes the path, a JSON API, a clean 404.

The verdicts recorded are PYTHON's. If engine.py's logic changes, this file
changes with it and the JS test fails until the port catches up.

    python3 test/gen_rule_cases.py ../kumo-domain-recon-tool
"""
import importlib.util
import json
import os
import sys

REPO = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "../kumo-domain-recon-tool")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rule_cases.json")

spec = importlib.util.spec_from_file_location("kumo_engine", os.path.join(REPO, "engine.py"))
eng = importlib.util.module_from_spec(spec)
sys.modules["kumo_engine"] = eng
spec.loader.exec_module(eng)

RULES = eng.VULN_RULES + eng.VULN_RULES_EXTENDED


class Resp:
    """The slice of requests.Response the matchers read."""
    def __init__(self, status, headers, body):
        self.status_code = status
        self.headers = headers
        self.text = body
        self.content = body.encode("utf-8", "replace")
        self.url = "http://target.test/"


def positive_for(rule):
    """Synthesise a response that this rule's matchers should accept."""
    status, body, headers = 200, [], {}
    for m in rule.get("matchers") or []:
        t = m.get("type", "word")
        if t == "status" and m.get("status"):
            status = m["status"][0]
        elif t == "word" and not m.get("negative"):
            target = headers if m.get("part") in ("header", "all_headers") else None
            for w in m.get("words") or []:
                if target is None:
                    body.append(str(w))
                else:
                    headers.setdefault("X-Synth", "")
                    headers["X-Synth"] += " " + str(w)
        elif t == "version":
            # a version well below any fix boundary
            headers["X-Powered-By"] = "PHP/5.4.0"
    text = "\n".join(body) if body else "synthetic"
    return status, headers, text


BENIGN = {
    "spa-shell": (200, {"Content-Type": "text/html"},
                  "<!doctype html><html><head><title>App</title>"
                  "<div id=root></div><script src=/static/app.js></script></html>"),
    "soft-404": (200, {"Content-Type": "text/html"},
                 "<!doctype html><html><body><h1>Page not found</h1>"
                 "<p>Sorry, we could not find that page.</p></body></html>"),
    "catchall-echo": (200, {"Content-Type": "text/html"},
                      "<!doctype html><html><body>No route for "
                      "/.env /config.php /.git/config</body></html>"),
    "json-api": (200, {"Content-Type": "application/json"},
                 '{"status":"ok","data":[],"version":"1.0","profile":null}'),
    "clean-404": (404, {"Content-Type": "text/html"},
                  "<!doctype html><html><body>404</body></html>"),
    "empty-200": (200, {}, ""),
}

cases = []
for i, rule in enumerate(RULES):
    st, hd, bd = positive_for(rule)
    cases.append({
        "label": f"{rule['id']} / positive", "rule_ix": i,
        "status": st, "headers": hd, "body": bd,
        "expect": bool(eng._eval_rule(Resp(st, hd, bd), dict(rule))),
    })

for name, (st, hd, bd) in BENIGN.items():
    for i, rule in enumerate(RULES):
        cases.append({
            "label": f"{rule['id']} / {name}", "rule_ix": i,
            "status": st, "headers": hd, "body": bd,
            "expect": bool(eng._eval_rule(Resp(st, hd, bd), dict(rule))),
        })

# Rules go out as a LIST and cases reference them by index. Keying by id would
# collapse any duplicate, and the two engines would then evaluate different
# rules while appearing to disagree.
json.dump({"rules": RULES, "cases": cases}, open(OUT, "w"))
pos = [c for c in cases if c["label"].endswith("/ positive")]
print(f"wrote {OUT}")
print(f"  rules            : {len(RULES)}")
print(f"  cases            : {len(cases)}")
print(f"  python fires on  : {sum(c['expect'] for c in cases)}")
print(f"    of which positive fixtures: {sum(c['expect'] for c in pos)}/{len(pos)}")
for name in BENIGN:
    n = sum(c["expect"] for c in cases if c["label"].endswith("/ " + name))
    print(f"    {name:16}: {n} rule(s) fire")
