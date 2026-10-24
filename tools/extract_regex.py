"""Extract (re.compile(...), label, severity) tuples and convert the patterns
to JavaScript. Python's inline (?i) has no JS equivalent, so it is hoisted to
the flags; anything else that JS cannot express is reported rather than
silently shipped broken."""
import ast
import json
import os
import re
import sys

REPO, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
src = open(os.path.join(REPO, "engine.py")).read()
tree = ast.parse(src)


def const_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def compiled_pattern(node):
    """(_re.compile(r'...') | re.compile(r'...')) -> the pattern string"""
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    if isinstance(f, ast.Attribute) and f.attr == "compile":
        if node.args:
            return const_str(node.args[0])
    return None


found = {}
for fn in ast.walk(tree):
    if not isinstance(fn, ast.FunctionDef):
        continue
    rows = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Tuple) or not node.elts:
            continue
        pat = compiled_pattern(node.elts[0])
        if pat is None:
            continue
        rest = [const_str(e) for e in node.elts[1:]]
        rows.append([pat] + rest)
    if rows:
        found[fn.name] = rows


def to_js(pat):
    """Return (jsPattern, flags, notes)."""
    flags, notes = "", []
    # hoist leading/embedded inline flags
    def hoist(m):
        nonlocal flags
        for ch in m.group(1):
            if ch == "i" and "i" not in flags:
                flags += "i"
            elif ch == "s":
                notes.append("(?s) -> JS 's' flag")
            elif ch == "m" and "m" not in flags:
                flags += "m"
            elif ch == "x":
                notes.append("(?x) verbose mode has no JS equivalent")
        return ""
    js = re.sub(r"\(\?([aimsux]+)\)", hoist, pat)
    if "(?s)" in pat and "s" not in flags:
        flags += "s"
    # Python-only constructs
    js2 = re.sub(r"\(\?P<(\w+)>", r"(?<\1>", js)      # named groups
    if js2 != js:
        notes.append("named groups converted")
        js = js2
    if "(?P=" in js:
        notes.append("UNSUPPORTED: named backreference")
    if re.search(r"\(\?#", js):
        notes.append("UNSUPPORTED: inline comment")
    return js, flags, notes


out = {}
report = []
for fnname, rows in found.items():
    conv = []
    for row in rows:
        js, flags, notes = to_js(row[0])
        conv.append({"re": js, "flags": flags,
                     "label": row[1] if len(row) > 1 else None,
                     "severity": row[2] if len(row) > 2 else None})
        if notes:
            report.append((fnname, row[1], notes))
    out[fnname] = conv

with open(os.path.join(OUT, "regex_tuples.json"), "w") as f:
    json.dump(out, f, separators=(',', ':'))

for fnname, rows in out.items():
    sev = [r for r in rows if r["severity"]]
    print(f"{fnname:26} {len(rows):>4} patterns  ({len(sev)} with severity)")
print()
if report:
    print("conversion notes:")
    for fn, label, notes in report:
        print(f"  {fn}/{label}: {'; '.join(notes)}")
else:
    print("no Python-only regex constructs found")
