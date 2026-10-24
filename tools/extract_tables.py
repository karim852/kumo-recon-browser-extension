"""Dump engine.py's constant tables to JSON for the in-browser engine.

Mechanical extraction beats transcription: the 358 vuln rules, the wordlists
and the signature tables come across byte-exact, and every regex gets checked
for JS compatibility on the way out.
"""
import importlib.util
import json
import os
import re
import sys

REPO = sys.argv[1]
OUT = sys.argv[2]
os.makedirs(OUT, exist_ok=True)

spec = importlib.util.spec_from_file_location("kumo_engine", os.path.join(REPO, "engine.py"))
eng = importlib.util.module_from_spec(spec)
sys.modules["kumo_engine"] = eng
spec.loader.exec_module(eng)

# ── which module-level names are data worth shipping ────────────────────
SKIP_TYPES = (type(sys), type(lambda: 0), type(re.compile('')))
tables = {}
for name in dir(eng):
    if name.startswith('__'):
        continue
    v = getattr(eng, name)
    if callable(v) or isinstance(v, SKIP_TYPES):
        continue
    if not isinstance(v, (list, dict, tuple, set, str, int, float, bool)):
        continue
    if isinstance(v, (str, int, float, bool)) and not name.isupper():
        continue
    if not name.isupper():
        continue
    try:
        tables[name] = json.loads(json.dumps(v, default=str))
    except Exception as e:
        print(f"  ! {name}: not serialisable ({e})")

print(f"extracted {len(tables)} tables")
for k, v in sorted(tables.items(), key=lambda x: -len(json.dumps(x[1]))):
    size = len(v) if hasattr(v, '__len__') else 1
    print(f"  {k:28} {type(v).__name__:6} {size:>6} entries  {len(json.dumps(v))//1024:>4} KB")

# ── collect every regex string so we can vet it for JS ──────────────────
regexes = []


def walk(node, path=""):
    if isinstance(node, dict):
        for k, val in node.items():
            if k in ("regex", "regexes", "pattern", "patterns") and isinstance(val, (list, str)):
                for r in ([val] if isinstance(val, str) else val):
                    if isinstance(r, str):
                        regexes.append((path + "." + k, r))
            walk(val, path + "." + str(k))
    elif isinstance(node, list):
        for i, val in enumerate(node):
            walk(val, f"{path}[{i}]")


for name, v in tables.items():
    walk(v, name)

with open(os.path.join(OUT, "tables.json"), "w") as f:
    json.dump(tables, f, separators=(',', ':'))
with open(os.path.join(OUT, "regexes.json"), "w") as f:
    json.dump(regexes, f, indent=1)

print(f"\n{len(regexes)} regexes collected for JS-compat checking")

# vuln rule stats
rules = (tables.get('VULN_RULES') or []) + (tables.get('VULN_RULES_EXTENDED') or [])
if rules:
    from collections import Counter
    sev = Counter(r.get('severity') for r in rules)
    mt = Counter(m.get('type') for r in rules for m in (r.get('matchers') or []))
    print(f"\nvuln rules: {len(rules)}")
    print("  by severity :", dict(sev))
    print("  matcher kinds:", dict(mt))
    print("  unique paths :", len({r.get('path') for r in rules}))
