"""
Generate version-matcher cases with engine.py's own verdicts, for the JS side
to check itself against.

The point is that the verdicts are PYTHON's, not hand-written: if engine.py's
boundary logic changes, this file changes with it and the JS test starts
failing until the port is updated too.

    python3 test/gen_version_cases.py ../kumo-domain-recon-tool
"""
import importlib.util
import json
import os
import sys

REPO = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "../kumo-domain-recon-tool")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "version_cases.json")

spec = importlib.util.spec_from_file_location("kumo_engine", os.path.join(REPO, "engine.py"))
eng = importlib.util.module_from_spec(spec)
sys.modules["kumo_engine"] = eng
spec.loader.exec_module(eng)

VERSIONS = [
    "8.5.12", "8.4.27", "8.3.36", "8.2.35", "8.5.20",
    "8.5.11", "8.4.26", "8.4.0", "8.3.35", "8.3.0", "8.2.34", "8.2.0",
    "8.1.33", "8.1.0", "8.0.30", "8.0.0", "7.4.33", "7.3.33", "7.2.24",
    "7.1.33", "7.0.33", "7.0.0", "5.6.40", "5.5.38", "5.4.45", "5.4.0",
    "5.3.29", "5.2.17", "5.0.0", "4.4.9",
    # shapes that must not become a finding by accident
    "8.3", "8", "not-a-version", "", "8.3.7-1ubuntu2", "v8.2.0",
]
STYLES = {
    "x-powered-by": lambda v: {"X-Powered-By": f"PHP/{v}"},
    "server":       lambda v: {"Server": f"Apache/2.4.62 (Debian) PHP/{v}"},
    "no-version":   lambda v: {"Server": "nginx"},
}

rules = {r["id"]: r for r in (eng.VULN_RULES + eng.VULN_RULES_EXTENDED)
         if any(m.get("type") == "version" for m in (r.get("matchers") or []))}
if not rules:
    sys.exit("no version rules found in engine.py")


class Resp:
    """The slice of a requests.Response that the matchers actually read."""
    def __init__(self, status, headers, body):
        self.status_code = status
        self.headers = headers
        self.text = body
        self.content = body.encode()
        self.url = "http://x/"


cases = []
for v in VERSIONS:
    for style, mk in STYLES.items():
        if style == "no-version" and v != VERSIONS[0]:
            continue                      # one no-version case is enough
        headers = mk(v)
        resp = Resp(200, headers, "<html><body>ok</body></html>")
        expect = {}
        for rid, rule in rules.items():
            scrubbed = dict(rule)
            expect[rid] = bool(eng._eval_rule(resp, scrubbed))
        cases.append({
            "label": f"{v or '(empty)'} via {style}",
            "status": 200, "headers": headers,
            "body": "<html><body>ok</body></html>",
            "expect": expect,
        })

json.dump({"rules": rules, "cases": cases}, open(OUT, "w"), indent=1)
print(f"wrote {OUT}")
print(f"  version rules : {sorted(rules)}")
print(f"  cases         : {len(cases)}")
fired = {rid: sum(1 for c in cases if c['expect'][rid]) for rid in rules}
print(f"  python says fires: {fired}")
