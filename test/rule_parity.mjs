/*
   Cross-engine parity for the whole rule playbook.

   The browser engine ships engine.py's rules, so it must reach engine.py's
   verdicts. Every rule is evaluated against a synthesised positive response
   and against the benign shapes that cause false positives in the field.
   Verdicts come from Python; any disagreement is a port bug.

   One limit worth knowing: gen_rule_cases.py synthesises a positive body from
   a rule's WORD matchers only, so a rule whose evidence is a regex gets a body
   that satisfies nothing. Python then does not fire either, both sides agree,
   and the rule is never really exercised -- 13 rules sit in that gap today.
   A pattern that is valid in Python but not in JS therefore passed this suite
   while the rule was dead in the browser, which is how three of them shipped
   with Python's inline (?m). The compile check below closes that hole: a rule
   whose pattern cannot compile can never fire, whatever the verdicts say.

       python3 test/gen_rule_cases.py ../kumo-domain-recon-tool
       node test/rule_parity.mjs
*/
import { readFileSync } from 'node:fs';
import { ruleMatches, patternCompiles } from '../src/engine/matcher.js';

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

/* ── every pattern must survive the trip into JS ─────────────
   Python's re accepts things JS's RegExp rejects outright: an inline (?i)
   or (?m) prefix, named groups in Python's (?P<x>) form, a possessive
   quantifier. The matcher swallows a bad pattern on purpose -- one broken
   rule must not kill a scan -- so such a rule simply never fires, in
   silence. That is invisible to a verdict comparison whenever Python does
   not fire either, so check the patterns themselves. */
const dead = [];
for (const rule of rules) {
  for (const m of rule.matchers || []) {
    for (const pat of (m.type === 'regex' ? (m.regex || m.patterns || []) : [])) {
      // Ask the matcher itself, so this cannot drift from what it accepts.
      if (!patternCompiles(pat)) dead.push({ id: rule.id, pat });
    }
  }
}

const pats = rules.reduce((a, r) => a + (r.matchers || [])
  .reduce((b, m) => b + (m.type === 'regex' ? (m.regex || m.patterns || []).length : 0), 0), 0);
console.log(`\n${B}every rule pattern must compile in JS${X}  ${D}(${pats} patterns)${X}\n`);
if (dead.length) {
  console.log(`  ${R}${dead.length} pattern(s) cannot compile -- those rules can never fire:${X}`);
  for (const d of dead.slice(0, 25)) {
    console.log(`  ${R}dead${X} ${d.id.padEnd(34)} ${D}${d.pat.slice(0, 60)}${X}`);
  }
  process.exit(1);
}
console.log(`  ${G}ok  ${X} all ${pats} rule patterns compile`);

const benign = [...byShape].filter(([k]) => k !== 'positive');
const anyBenign = benign.reduce((a, [, s]) => a + s.firedJs, 0);
console.log(`\n${G}every one of the ${cases.length} cases matches engine.py's verdict${X}`);
console.log(`${G}no rule fires on any of the ${benign.length} benign response shapes${X}`
  + (anyBenign ? ` ${R}(${anyBenign} did!)${X}` : ''));
