"""Pull function-local literal tables (wordlists, signatures, templates) out of
engine.py via AST, so the JS port uses the same data rather than a retyped
approximation."""
import ast
import json
import os
import sys

REPO, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
src = open(os.path.join(REPO, "engine.py")).read()
tree = ast.parse(src)

WANT = {
    "scan_endpoints", "scan_cloud_buckets", "_wafw00f_python", "_whatweb_python",
    "scan_js_secrets", "generate_dorks", "generate_osint_urls", "scan_api_fuzzer",
    "scan_content_intel", "scan_subdomains", "scan_bruteforce", "scan_headers",
    "scan_http_inspect", "scan_breachintel", "scan_screenshot", "scan_favicon",
}

out = {}
for node in ast.walk(tree):
    if not isinstance(node, ast.FunctionDef) or node.name not in WANT:
        continue
    locals_found = {}
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Assign):
            continue
        for tgt in sub.targets:
            if not isinstance(tgt, ast.Name):
                continue
            try:
                val = ast.literal_eval(sub.value)
            except Exception:
                continue
            if isinstance(val, (list, dict, tuple, set)) and len(val) >= 3:
                if isinstance(val, (set, tuple)):
                    val = list(val)
                locals_found[tgt.id] = val
    if locals_found:
        out[node.name] = locals_found

print(f"{'function':24} {'table':26} {'n':>5}  kind")
print("-" * 68)
total = 0
for fn, tabs in out.items():
    for name, v in tabs.items():
        kind = "dict" if isinstance(v, dict) else "list"
        inner = ""
        if isinstance(v, list) and v and isinstance(v[0], (list, tuple)):
            inner = f"of {len(v[0])}-tuples"
        elif isinstance(v, list) and v:
            inner = f"of {type(v[0]).__name__}"
        print(f"{fn:24} {name:26} {len(v):>5}  {kind} {inner}")
        total += len(v)

with open(os.path.join(OUT, "locals.json"), "w") as f:
    json.dump(out, f, separators=(',', ':'), default=str)
print(f"\n{total} total entries across {sum(len(t) for t in out.values())} tables")
