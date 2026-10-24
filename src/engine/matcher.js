/* ════════════════════════════════════════════════════════════
   The nuclei-style matcher, ported from engine.py.

   A rule fires when its matchers agree under matchers_condition.
   Four matcher kinds are in use across the 365 rules:
     status  — response code is in a set
     word    — literal strings in body/header, and/or
     regex   — pattern against body/header
     dsl     — the handful of helpers engine.py defines
   ════════════════════════════════════════════════════════════ */

const reCache = new Map();
function rx(pattern, flags = '') {
  const key = pattern + '\u0000' + flags;
  let r = reCache.get(key);
  if (r === undefined) {
    try { r = new RegExp(pattern, flags); }
    catch { r = null; }          // a bad pattern must never kill a scan
    reCache.set(key, r);
  }
  return r;
}

/* What a matcher looks at. */
function part(res, which) {
  switch (which) {
    case 'header':
    case 'all_headers':
      return Object.entries(res.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
    case 'all':
      return (Object.entries(res.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')
        + '\n\n' + (res.body || ''));
    case 'body':
    default:
      return res.body || '';
  }
}

/* The DSL helpers engine.py actually uses in its rules. */
function dslOk(expr, res) {
  const body = res.body || '';
  const len = res.bytes || body.length;
  const e = String(expr || '').trim();

  if (e === 'not_html') {
    // A "file exposed" hit that returns the SPA shell is a false positive.
    return !/<\s*(!doctype\s+html|html|head|body)\b/i.test(body.slice(0, 2000));
  }
  if (e === 'is_html') return /<\s*(!doctype\s+html|html)\b/i.test(body.slice(0, 2000));
  if (e === 'not_empty') return body.trim().length > 0;

  let m = e.match(/^content_length\s*(<=|>=|<|>|==)\s*(\d+)$/);
  if (m) {
    const n = Number(m[2]);
    switch (m[1]) {
      case '<': return len < n;
      case '>': return len > n;
      case '<=': return len <= n;
      case '>=': return len >= n;
      case '==': return len === n;
    }
  }
  m = e.match(/^status_code\s*==\s*(\d+)$/);
  if (m) return res.status === Number(m[1]);

  // Unknown DSL: don't let it manufacture a finding.
  return false;
}

function matcherHits(m, res) {
  const neg = !!m.negative;
  let hit = false;

  switch (m.type) {
    case 'status':
      hit = (m.status || []).includes(res.status);
      break;

    case 'word': {
      const hay = part(res, m.part);
      const hayLc = m.case_insensitive === false ? hay : hay.toLowerCase();
      const words = (m.words || []).map(w =>
        m.case_insensitive === false ? String(w) : String(w).toLowerCase());
      hit = (m.condition === 'and')
        ? words.every(w => hayLc.includes(w))
        : words.some(w => hayLc.includes(w));
      break;
    }

    case 'regex': {
      const hay = part(res, m.part);
      const pats = m.regex || m.patterns || [];
      const test = p => { const r = rx(p, m.flags || 'm'); return r ? r.test(hay) : false; };
      hit = (m.condition === 'and') ? pats.every(test) : pats.some(test);
      break;
    }

    case 'dsl': {
      const exprs = m.dsl || [];
      hit = (m.condition === 'or') ? exprs.some(x => dslOk(x, res)) : exprs.every(x => dslOk(x, res));
      break;
    }

    case 'size':
      hit = (m.size || []).includes(res.bytes);
      break;

    default:
      hit = false;
  }
  return neg ? !hit : hit;
}

/* Does this response satisfy the rule? */
export function ruleMatches(rule, res) {
  const ms = rule.matchers || [];
  if (!ms.length) return false;
  return (rule.matchers_condition === 'or')
    ? ms.some(m => matcherHits(m, res))
    : ms.every(m => matcherHits(m, res));
}

/* Group rules by path so one request can settle several rules. */
export function groupByPath(rules) {
  const byPath = new Map();
  for (const r of rules) {
    const p = r.path || '/';
    if (!byPath.has(p)) byPath.set(p, []);
    byPath.get(p).push(r);
  }
  return byPath;
}
