/* ════════════════════════════════════════════════════════════
   The nuclei-style matcher, ported from engine.py.

   A rule fires when its matchers agree under matchers_condition.
   Five matcher kinds are in use across the 420 rules:
     status  — response code is in a set
     word    — literal strings in body/header, and/or
     regex   — pattern against body/header
     dsl     — the handful of helpers engine.py defines
     version — is the advertised version in a vulnerable range
   ════════════════════════════════════════════════════════════ */

import { DATA } from './data/tables.js';

const reCache = new Map();

/* Rules come from engine.py, where a pattern may carry Python's inline
   (?im) prefix. JS has no inline form and throws on it, so the group is
   hoisted to real flags. Without this, a rule like env-file compiles to
   null and silently never fires -- an exposed .env goes unreported. */
function hoistInlineFlags(pattern, flags) {
  const m = /^\(\?([imsx]+)\)/.exec(pattern);
  if (!m) return [pattern, flags];
  const extra = m[1].replace(/x/g, '');     // Python's verbose flag has no JS form
  return [pattern.slice(m[0].length), [...new Set(flags + extra)].join('')];
}

function rx(pattern, flags = '') {
  const key = pattern + '\u0000' + flags;
  let r = reCache.get(key);
  if (r === undefined) {
    const [pat, fl] = hoistInlineFlags(String(pattern), flags);
    try { r = new RegExp(pat, fl); }
    catch { r = null; }          // a bad pattern must never kill a scan
    reCache.set(key, r);
  }
  return r;
}

/* Whether the matcher can actually use a pattern. rx() returns null for one
   it cannot compile, and a rule holding such a pattern can never fire -- so
   the parity suite asserts on this rather than re-deriving the rules here. */
export const patternCompiles = (pattern, flags = 'm') => rx(pattern, flags) !== null;

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

/* ── version comparison ──────────────────────────────────────
   A word matcher cannot do arithmetic on a version, so
   version-boundary CVEs could not be expressed as rules at all.
   Ported from engine.py's _vparse / _vcmp / _match_version. */

/* '8.3.7-1ubuntu2' -> [8, 3, 7]. Build and distro cruft is ignored. */
function vparse(v) {
  const m = /^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(String(v == null ? '' : v));
  if (!m) return null;
  return [1, 2, 3].map(i => (m[i] ? parseInt(m[i], 10) : 0));
}

/* -1, 0 or 1; null if either side is unparseable. */
function vcmp(a, b) {
  const pa = vparse(a), pb = vparse(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

/*
   Is the advertised version in a known-vulnerable range?

   Strict about evidence, the same way engine.py is: the version must be READ
   out of the response. No version advertised means no match — never a guess,
   and never a finding inferred from the product merely being present.

     fixed_in                   branch prefix -> the release that fixed it
     unfixed_branches_affected  a branch with no fix (end of life) is affected
     min_affected / max_affected bound the range, so an ancient unrelated
                                version or a garbage parse cannot match
*/
function matchVersion(m, res) {
  const hay = part(res, m.part || 'header');
  if (!hay) return false;

  const pats = Array.isArray(m.regex) ? m.regex : (m.regex ? [m.regex] : []);
  let found = null;
  for (const p of pats) {
    const r = rx(p, m.case_sensitive ? '' : 'i');
    if (!r) continue;
    const mm = r.exec(hay);
    if (mm) { found = (mm[1] !== undefined ? mm[1] : mm[0]).trim(); break; }
  }
  if (!found || !vparse(found)) return false;

  if (m.min_affected && (vcmp(found, m.min_affected) || 0) < 0) return false;
  if (m.max_affected && (vcmp(found, m.max_affected) || 0) > 0) return false;

  const parts = vparse(found);
  const fixed = m.fixed_in || {};
  // Most specific branch wins ("8.3" before "8"), so a per-branch fix table
  // behaves the way its author wrote it.
  for (const depth of [2, 1]) {
    const branch = parts.slice(0, depth).join('.');
    if (Object.prototype.hasOwnProperty.call(fixed, branch)) {
      return (vcmp(found, fixed[branch]) || 0) < 0;
    }
  }
  return !!m.unfixed_branches_affected;
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

    case 'version':
      hit = matchVersion(m, res);
      break;

    case 'size':
      hit = (m.size || []).includes(res.bytes);
      break;

    default:
      hit = false;
  }
  return neg ? !hit : hit;
}

/* ── the evidence floor ──────────────────────────────────────
   Ported from engine.py's _is_strong_evidence /
   _matcher_has_strong_hit, and applied in ruleMatches below.

   Nuclei templates list several alternative indicators per
   template. Kumo's porting pipeline flattened those blocks into
   one OR list and dropped their `condition: and`, so a single
   generic token ("title", "version", "profile") was enough to
   claim a finding. That was the largest single source of false
   positives in the playbook. A rule that identifies a product by
   words must now have at least one word matcher satisfied by a
   SPECIFIC token. */

/* Strip quoting and punctuation so matcher words compare as plain tokens. */
function normToken(w) {
  return String(w == null ? '' : w)
    .trim()
    .replace(/^["'`:,;=<>[\](){}\s\t]+/, '')
    .replace(/["'`:,;=<>[\](){}\s\t]+$/, '')
    .toLowerCase();
}

/* Specificity comes from the curated weak list, not from length: real product
   tokens are often short ("traefik", "grafana", "UP") while the tokens that
   cause false positives are ordinary web vocabulary. */
const WEAK = new Set((DATA.WEAK_EVIDENCE || []).map(normToken));

function isStrongEvidence(word) {
  const tok = normToken(word);
  if (!tok || WEAK.has(tok)) return false;
  return tok.length >= 2;
}

/* Was this word matcher satisfied by at least one specific word? */
function matcherHasStrongHit(m, res) {
  if ((m.type || 'word') !== 'word' || m.negative) return false;
  const words = m.words || [];
  if (!words.length) return false;

  let hay = part(res, m.part || 'body');
  let probe;
  if (!m.case_sensitive) {
    hay = hay.toLowerCase();
    probe = words.map(w => [w, String(w).toLowerCase()]);
  } else {
    probe = words.map(w => [w, String(w)]);
  }
  const matched = probe.filter(([, needle]) => hay.includes(needle)).map(([w]) => w);
  if (!matched.length) return false;

  // A list that is one word in several casings is a single alternative, not a
  // menu of weak options.
  if (new Set(words.map(normToken)).size <= 1) return true;
  return matched.some(isStrongEvidence);
}

/* ── raw-file paths must not answer with HTML ─────────────────
   Ported from engine.py's _is_rawfile_path / _looks_like_html.

   A rule claiming a raw file is exposed cannot be satisfied by an
   HTML page: an article mentioning DB_PASSWORD is not an exposed
   credentials file, and a rendered page served where /.env was
   requested is the app's own routing. Rules that deliberately
   target an HTML product page (panels, dashboards) are unaffected,
   because this applies only to paths that name a config or secret
   file. */

const RAWFILE_EXT = DATA.RAWFILE_EXT || [];
const RAWFILE_TOKENS = [
  '/.git', '/.svn', '/.hg', '.htpasswd', '.htaccess', '.env', 'wp-config',
  '.ds_store', 'backup', 'dump', '.sql', '.bak', 'database', 'db.sqlite',
  '/.aws', 'config.php.bak', 'credentials', 'id_rsa', 'id_dsa', 'id_ecdsa',
];

export function isRawfilePath(path) {
  const p = String(path || '').toLowerCase().split('?')[0].split('#')[0];
  if (!p) return false;
  if (p.endsWith('/')) return false;   // a directory: "Index of /…" is real HTML
  if (RAWFILE_TOKENS.some(t => p.includes(t))) return true;
  const base = p.replace(/\/+$/, '').split('/').pop();
  if (base.startsWith('.') && base.length > 1) return true;  // .npmrc, .s3cfg
  return RAWFILE_EXT.some(e => base.endsWith(e));
}

export function looksLikeHtml(body) {
  const head = String(body || '').slice(0, 512).replace(/^\s+/, '').toLowerCase();
  return head.startsWith('<!doctype') || head.startsWith('<html')
    || head.slice(0, 200).includes('<head') || head.slice(0, 300).includes('<body');
}

/* Does this response satisfy the rule? */
export function ruleMatches(rule, res) {
  const ms = rule.matchers || [];
  if (!ms.length) return false;

  // A raw-file rule answered with an HTML document is the app shell, not the
  // file. Checked before the matchers, exactly as engine.py does.
  if (rule.path && isRawfilePath(rule.path) && looksLikeHtml(res.body)) return false;

  const results = ms.map(m => matcherHits(m, res));
  const fired = (rule.matchers_condition === 'or')
    ? results.some(Boolean)
    : results.every(Boolean);
  if (!fired) return false;

  // A satisfied version matcher is strong evidence on its own: it read a real
  // version out of the response and compared it against a fix boundary.
  if (ms.some((m, i) => results[i] && m.type === 'version')) return true;

  const wordMatchers = ms.filter((m, i) =>
    results[i] && (m.type || 'word') === 'word' && !m.negative);
  if (wordMatchers.length && !wordMatchers.some(m => matcherHasStrongHit(m, res))) {
    return false;
  }
  return true;
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
