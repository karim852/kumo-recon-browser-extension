"""
Build src/engine/data/tables.js from engine.py — the whole pipeline in one
step.

The browser engine runs on the same data as engine.py rather than a retyped
approximation, so this is mechanical. Three sources feed it:

  module-level constants   via import (extract_tables.py's approach)
  function-local literals  via AST literal_eval (extract_locals.py's)
  re.compile tuples        via AST, with the pattern converted for JS

Run it after any change to engine.py's tables:

    python3 tools/build_tables.py ../kumo-domain-recon-tool

Nothing here is hand-maintained. If a table moves inside a function, add that
function to LOCAL_WANT; if it moves to module level, it is picked up for free.
"""
import ast
import json
import importlib.util
import os
import re
import sys

REPO = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "../kumo-domain-recon-tool")
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "src", "engine", "data", "tables.js")

# ── load engine.py ────────────────────────────────────────────────────────
spec = importlib.util.spec_from_file_location("kumo_engine", os.path.join(REPO, "engine.py"))
eng = importlib.util.module_from_spec(spec)
sys.modules["kumo_engine"] = eng
spec.loader.exec_module(eng)
src = open(os.path.join(REPO, "engine.py")).read()
tree = ast.parse(src)


def jsonable(v):
    """
    Sets and tuples have no JSON form. Sets become sorted arrays.

    Bytes need decoding, not str(): engine.py stores file-content markers as
    bytes, and str(b'DB_NAME') is the literal "b'DB_NAME'", which shipped to
    the extension as a marker that could never match anything.
    """
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", "replace")
    if isinstance(v, (set, frozenset)):
        try:
            return sorted(v)
        except TypeError:
            return sorted(v, key=str)
    if isinstance(v, (tuple, list)):
        return [jsonable(x) for x in v]
    if isinstance(v, dict):
        return {str(k): jsonable(x) for k, x in v.items()}
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)


# ── function-local literals ───────────────────────────────────────────────
LOCAL_WANT = {
    "scan_ports", "scan_endpoints", "scan_cloud_buckets", "_wafw00f_python",
    "_whatweb_python", "scan_js_secrets", "scan_api_fuzzer", "scan_content_intel",
    "scan_subdomains", "scan_bruteforce", "scan_headers", "scan_http_inspect",
    "scan_favicon",
}
locals_found = {}
for node in ast.walk(tree):
    if not isinstance(node, ast.FunctionDef) or node.name not in LOCAL_WANT:
        continue
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
                locals_found[f"{node.name}.{tgt.id}"] = jsonable(val)


# ── re.compile(...) secret patterns ───────────────────────────────────────
def py_regex_to_js(p):
    """Python inline (?i) has no JS form; hoist it to a flag."""
    flags = ""
    if "(?i)" in p:
        flags += "i"
        p = p.replace("(?i)", "")
    p = re.sub(r"\(\?P<[^>]+>", "(", p)      # named groups -> plain groups
    return p, flags


secret_patterns = []
for node in ast.walk(tree):
    if not (isinstance(node, ast.FunctionDef) and node.name == "scan_js_secrets"):
        continue
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Assign):
            continue
        for tgt in sub.targets:
            if not (isinstance(tgt, ast.Name) and tgt.id == "SECRET_PATTERNS"):
                continue
            for el in getattr(sub.value, "elts", []):
                parts = getattr(el, "elts", [])
                if len(parts) != 3:
                    continue
                call = parts[0]
                pat = None
                if isinstance(call, ast.Call) and getattr(call.args, "__len__", lambda: 0)():
                    a0 = call.args[0]
                    if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                        pat = a0.value
                elif isinstance(call, ast.Constant) and isinstance(call.value, str):
                    pat = call.value
                if pat is None:
                    continue
                label = parts[1].value if isinstance(parts[1], ast.Constant) else None
                sev = parts[2].value if isinstance(parts[2], ast.Constant) else None
                js, fl = py_regex_to_js(pat)
                secret_patterns.append([js, label, sev, fl])

# ── assemble exactly the keys the JS consumes ─────────────────────────────
G = lambda n: jsonable(getattr(eng, n))
L = locals_found.get

DATA = {
    "_note": "Generated from engine.py by tools/build_tables.py — do not hand-edit.",

    # the rule playbook: both lists merged, as the browser engine sees one set
    "VULN_RULES": G("VULN_RULES") + G("VULN_RULES_EXTENDED"),

    "ENDPOINTS":                L("scan_endpoints.ENDPOINTS"),
    "SEV_ORDER":                L("scan_endpoints.sev_order"),
    "KNOWN_PORTS":              L("scan_ports.KNOWN_PORTS"),
    "BRUTE_WORDLIST":           L("scan_bruteforce.wordlist"),
    "SENSITIVE_PREFIXES":       L("scan_subdomains.sensitive_prefixes"),

    # whatweb: the signature table is module-level now, so it comes from the
    # import rather than from a literal the AST has to evaluate
    "WHATWEB_SIGNATURES":       G("_WW_SIGNATURES"),
    "WHATWEB_VERSION_PATTERNS": L("_whatweb_python.version_patterns"),
    "WHATWEB_COOKIE_HINTS":     L("_whatweb_python.cookie_hints"),

    "WAF_SIGNATURES":           L("_wafw00f_python.WAF_SIGNATURES"),
    "WAF_PROBE_PATHS":          L("_wafw00f_python.PROBE_PATHS"),
    "FAVICON_PATHS":            L("scan_favicon.FAVICON_PATHS"),
    "FAVICON_TECH_DB":          L("scan_favicon.FAVICON_TECH_DB"),
    "BUCKET_SUFFIXES":          L("scan_cloud_buckets.SUFFIXES"),
    "BUCKET_PREFIXES":          L("scan_cloud_buckets.PREFIXES"),
    "JS_SKIP_CDNS":             L("scan_js_secrets.SKIP_CDNS"),
    "CONTENT_SKIP_CDNS":        L("scan_content_intel.SKIP_CDNS"),
    "CONTENT_DOC_HOSTS":        L("scan_content_intel.DOC_HOSTS"),
    "HTTP_SEC_HEADERS":         L("scan_http_inspect.SEC"),
    "HTTP_STANDARD_HEADERS":    L("scan_http_inspect.STANDARD"),
    "HTTP_LEAKY_HEADERS":       L("scan_http_inspect.LEAKY"),
    "HEADER_CHECKS":            L("scan_headers.checks"),
    "API_BASES":                L("scan_api_fuzzer.API_BASES"),
    "API_ROOT_SPECS":           L("scan_api_fuzzer.ROOT_SPECS"),
    "API_ENDPOINT_PATHS":       L("scan_api_fuzzer.ENDPOINT_PATHS"),
    "SECRET_PATTERNS":          secret_patterns,
    "RAWFILE_MARKERS":          G("_RAWFILE_MARKERS"),
    "RAWFILE_EXT":              G("_RAWFILE_EXT"),

    # detection logic the matcher needs, previously not shipped at all
    "WEAK_EVIDENCE":            G("_WEAK_EVIDENCE"),
    "MULTI_SUFFIX":             G("_MULTI_SUFFIX"),
    "CLOUDFLARE_EDGE_PORTS":    G("_CLOUDFLARE_EDGE_PORTS"),

    # module 28 — CMS deep scan
    "CMS_SIGNALS":              G("_CMS_SIGNALS"),
    "CMS_PATHS":                G("_CMS_PATHS"),
    "CMS_PATH_MARKERS":         G("_CMS_PATH_MARKERS"),
    "CMS_VERSION_SOURCES":      G("_CMS_VERSION_SOURCES"),
    "CMS_NAMES":                G("_CMS_NAMES"),
    "CMS_DEEP_SCANNED":         G("_CMS_DEEP_SCANNED"),
    "WW_CMS_SIGS":              G("_WW_CMS_SIGS"),
    "WW_ECOM_SIGS":             G("_WW_ECOM_SIGS"),

    # module 29 — control panels
    "PANELS":                   G("_PANELS"),
    "CDN_PROXIED_PANEL_PORTS":  G("_CDN_PROXIED_PANEL_PORTS"),

    "DKIM_SELECTORS":           G("DKIM_SELECTORS"),
}

missing = [k for k, v in DATA.items() if v is None]
if missing:
    print("MISSING (a table moved or was renamed in engine.py):")
    for k in missing:
        print("   ", k)
    sys.exit(1)

body = json.dumps(DATA, separators=(",", ":"), ensure_ascii=False)
with open(OUT, "w", encoding="utf-8") as f:
    f.write("/* Generated from engine.py by tools/build_tables.py — do not hand-edit. */\n")
    f.write(f"export const DATA = {body};\n")

print(f"wrote {OUT}  ({len(body) // 1024} KB)")
print(f"  tables      : {len(DATA) - 1}")
print(f"  vuln rules  : {len(DATA['VULN_RULES'])}")
mt = {}
for r in DATA["VULN_RULES"]:
    for m in r.get("matchers") or []:
        mt[m.get("type")] = mt.get(m.get("type"), 0) + 1
print(f"  matchers    : {mt}")
print(f"  panels      : {len(DATA['PANELS'])}")
print(f"  cms paths   : {sum(len(v) for v in DATA['CMS_PATHS'].values())}")
print(f"  secrets     : {len(DATA['SECRET_PATTERNS'])}")
