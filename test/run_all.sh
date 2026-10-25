#!/usr/bin/env bash
# Every check the extension has. Run from the repo root:
#
#   ./test/run_all.sh [path-to-kumo-domain-recon-tool]
#
# The parity suites regenerate their cases from engine.py first, so they test
# the current engine rather than a snapshot. If engine.py's detection logic
# changes and the JS port is not updated, these fail.
set -uo pipefail
cd "$(dirname "$0")/.."
KUMO=${1:-../kumo-domain-recon-tool}
fail=0

run() {
  printf '\n\033[1m── %s\033[0m\n' "$1"; shift
  "$@" || fail=1
}

# The parity suites compare this engine against engine.py, so engine.py has to
# be here. Their case files are generated, not committed: they are large, and a
# stale snapshot would quietly stop testing the current engine.
if [ ! -d "$KUMO" ]; then
  printf '\033[91mmain repo not found at %s\033[0m\n' "$KUMO"
  printf 'The parity suites generate their cases from engine.py. Clone\n'
  printf 'karim852/KUMO-Domain-Recon-Tool beside this repo, or pass its path:\n\n'
  printf '    ./test/run_all.sh /path/to/kumo-domain-recon-tool\n\n'
  printf 'Running the suites that do not need it:\n'
  run "every renderer executes" node test/render_smoke.mjs
  run "fingerprints must not read prose" node test/fingerprint_parity.mjs
  exit "$fail"
fi

printf '\033[90mregenerating cases from %s\033[0m\n' "$KUMO"
python3 tools/build_tables.py "$KUMO" >/dev/null || fail=1
python3 test/gen_version_cases.py "$KUMO" >/dev/null || fail=1
python3 test/gen_rule_cases.py "$KUMO" >/dev/null || fail=1

run "rule playbook parity with engine.py" node test/rule_parity.mjs
run "version matcher parity with engine.py" node test/version_parity.mjs
run "fingerprints must not read prose"      node test/fingerprint_parity.mjs
run "every renderer executes"               node test/render_smoke.mjs

if [ "$fail" -eq 0 ]; then
  printf '\n\033[92mall suites passed\033[0m\n'
else
  printf '\n\033[91msome suites failed\033[0m\n'
fi
exit "$fail"
