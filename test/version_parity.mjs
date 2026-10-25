/*
   Cross-engine parity for the `version` matcher.

   The browser engine and engine.py must reach the same verdict on the same
   response, or the extension quietly disagrees with the tool it mirrors. The
   Python side writes its verdicts to version_cases.json; this re-runs every
   case through the JS matcher and fails on any disagreement.

       python3 test/gen_version_cases.py ../kumo-domain-recon-tool
       node test/version_parity.mjs
*/
import { readFileSync } from 'node:fs';
import { ruleMatches } from '../src/engine/matcher.js';

const G = '\x1b[92m', R = '\x1b[91m', D = '\x1b[90m', B = '\x1b[1m', X = '\x1b[0m';
const cases = JSON.parse(readFileSync(new URL('./version_cases.json', import.meta.url)));

let fails = [];
console.log(`${B}version matcher parity with engine.py${X}  ${D}(${cases.cases.length} cases)${X}\n`);

for (const c of cases.cases) {
  const res = { status: c.status, headers: c.headers, body: c.body || '', bytes: (c.body || '').length };
  for (const [ruleId, want] of Object.entries(c.expect)) {
    const rule = cases.rules[ruleId];
    if (!rule) { fails.push(`${ruleId} missing from shipped rules`); continue; }
    const got = ruleMatches(rule, res);
    if (got !== want) {
      fails.push(`${c.label} / ${ruleId}: python=${want} js=${got}`);
      console.log(`  ${R}FAIL${X} ${c.label.padEnd(30)} ${ruleId.padEnd(24)} python=${want} js=${got}`);
    }
  }
}

if (fails.length) {
  console.log(`\n${R}${fails.length} disagreement(s) with engine.py${X}`);
  process.exit(1);
}
console.log(`  ${G}ok${X}  every case matches engine.py's verdict`);
console.log(`\n${G}the browser matcher and engine.py agree on all ${cases.cases.length} version cases${X}`);
