/*
   Cross-engine parity for the whole rule playbook.

   The browser engine ships engine.py's rules, so it must reach engine.py's
   verdicts. Every rule is evaluated against a synthesised positive response
   and against the benign shapes that cause false positives in the field.
   Verdicts come from Python; any disagreement is a port bug.

       python3 test/gen_rule_cases.py ../kumo-domain-recon-tool
       node test/rule_parity.mjs
*/
import { readFileSync } from 'node:fs';
import { ruleMatches } from '../src/engine/matcher.js';

const G = '\x1b[92m', R = '\x1b[91m', Y = '\x1b[93m', D = '\x1b[90m', B = '\x1b[1m', X = '\x1b[0m';
const { rules, cases } = JSON.parse(readFileSync(new URL('./rule_cases.json', import.meta.url)));

const bad = [];
const byShape = new Map();

for (const c of cases) {
  const rule = rules[c.rule_ix];
  const res = {
    status: c.status, headers: c.headers,
    body: c.body || '', bytes: Buffer.byteLength(c.body || ''),
  };
  const got = ruleMatches(rule, res);
  const shape = c.label.split(' / ')[1];
  const s = byShape.get(shape) || { n: 0, firedPy: 0, firedJs: 0, diff: 0 };
  s.n++; if (c.expect) s.firedPy++; if (got) s.firedJs++;
  if (got !== c.expect) { s.diff++; bad.push({ ...c, got }); }
  byShape.set(shape, s);
}

console.log(`${B}rule playbook parity with engine.py${X}  `
  + `${D}(${rules.length} rules x ${byShape.size} response shapes `
  + `= ${cases.length} cases)${X}\n`);
console.log(`  ${'shape'.padEnd(16)}${'cases'.padStart(7)}${'python'.padStart(8)}${'js'.padStart(6)}${'diff'.padStart(6)}`);
for (const [shape, s] of byShape) {
  const mark = s.diff ? R : G;
  console.log(`  ${mark}${shape.padEnd(16)}${X}${String(s.n).padStart(7)}`
    + `${String(s.firedPy).padStart(8)}${String(s.firedJs).padStart(6)}`
    + `${mark}${String(s.diff).padStart(6)}${X}`);
}

if (bad.length) {
  console.log(`\n${R}${bad.length} disagreement(s):${X}`);
  for (const b of bad.slice(0, 25)) {
    console.log(`  ${b.label.padEnd(44)} python=${b.expect} js=${b.got}`);
  }
  if (bad.length > 25) console.log(`  ${D}... and ${bad.length - 25} more${X}`);
  process.exit(1);
}

const benign = [...byShape].filter(([k]) => k !== 'positive');
const anyBenign = benign.reduce((a, [, s]) => a + s.firedJs, 0);
console.log(`\n${G}every one of the ${cases.length} cases matches engine.py's verdict${X}`);
console.log(`${G}no rule fires on any of the ${benign.length} benign response shapes${X}`
  + (anyBenign ? ` ${R}(${anyBenign} did!)${X}` : ''));
