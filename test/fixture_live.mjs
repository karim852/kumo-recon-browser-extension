/*
   Run the real modules against test/fixture_site.py over real HTTP.

   The parity suites compare verdicts with engine.py, and the smoke suite
   proves every card renders. Neither looks at what a module actually FINDS,
   and that is a blind spot with teeth: js_secrets once read SECRET_PATTERNS
   as objects when the generator emits tuples, so it detected nothing at all
   and still passed every suite. Three rules shipped with Python's inline
   (?m), which JS rejects, so they could never fire -- also green.

   So this points the modules at the deliberately leaky fixture and asserts
   on the findings. A planted credential that stops being found fails here.

       node test/fixture_live.mjs

   The fixture is HTTPS with a self-signed certificate, generated on first
   run, hence the TLS override -- scoped to this process only.
*/
import { spawn, execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = '127.0.0.1:8732';
const G = '\x1b[92m', R = '\x1b[91m', D = '\x1b[90m', B = '\x1b[1m', X = '\x1b[0m';

const fails = [];
const check = (label, ok, detail = '') => {
  if (!ok) fails.push(label);
  console.log(`  ${ok ? G + 'ok  ' + X : R + 'FAIL' + X} ${label}` + (detail ? `  ${D}${detail}${X}` : ''));
};

/* ── the fixture's certificate, made once ─────────────────── */
const cert = join(HERE, 'cert.pem'), key = join(HERE, 'key.pem');
if (!existsSync(cert) || !existsSync(key)) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key, '-out', cert, '-days', '30', '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { stdio: 'ignore' });
}

const srv = spawn('python3', [join(HERE, 'fixture_site.py')], { stdio: 'ignore' });
const stop = () => { try { srv.kill(); } catch (_) {} };
process.on('exit', stop);

/* ── wait for it to answer ────────────────────────────────── */
let up = false;
for (let i = 0; i < 40 && !up; i++) {
  try { await fetch(`https://${TARGET}/`); up = true; }
  catch { await new Promise(r => setTimeout(r, 250)); }
}
if (!up) { console.log(`${R}fixture site never came up${X}`); stop(); process.exit(1); }

const { MODULES } = await import('../src/engine/registry.js');
const run = async key => {
  const m = MODULES.find(x => x.key === key);
  return m.run({ domain: TARGET, signal: new AbortController().signal });
};

console.log(`${B}the real modules against the leaky fixture${X}  ${D}(${TARGET})${X}\n`);

/* ── js_secrets: the module that once found nothing ───────── */
console.log(`${B}planted credentials must be found${X}`);
const js = await run('js_secrets');
const types = new Set((js.secrets || []).map(s => s.type));
for (const want of ['AWS Access Key ID', 'Stripe Live Secret Key', 'GitHub Personal Token',
                    'MongoDB URL', 'Google API Key']) {
  check(`finds ${want}`, types.has(want));
}
check('every secret carries a type and a severity',
  (js.secrets || []).length > 0 && (js.secrets || []).every(s => s.type && s.severity));
check('no secret is reported with an empty value',
  (js.secrets || []).every(s => s.value));
check('the live credential is redacted, never printed whole',
  !JSON.stringify(js).includes('AKIAIOSFODNN7EXAMPLE'));
check('attributed to the file it came from', (js.secrets || []).some(s => /app\.js$/.test(s.file || '')),
  `${js.secrets?.[0]?.file || ''}`);

/* ── rules whose only evidence is a regex ─────────────────── */
console.log(`\n${B}regex-only rules must still fire${X}`);
const nuclei = await run('nuclei');
const ids = new Set((nuclei.findings || []).map(f => f.rule_id));
check('env-file fires on the exposed .env', ids.has('env-file'),
  `${nuclei.total_found} finding(s)`);
check('.env is graded critical',
  (nuclei.findings || []).some(f => f.rule_id === 'env-file' && f.severity === 'critical'));

/* ── the rest of the leak surface ─────────────────────────── */
console.log(`\n${B}the rest of the planted leak surface${X}`);
const ep = await run('endpoints');
const paths = new Set((ep.findings || []).map(f => f.path));
check('/.env found', paths.has('/.env'));
check('/.git/config found', paths.has('/.git/config'));

const api = await run('api_fuzzer');
check('GraphQL introspection detected', !!api.graphql, api.graphql?.severity || '');
check('Swagger spec detected', (api.specs || []).length > 0);

const hdr = await run('headers');
check('weak header posture graded badly', /^[DEF]$/.test(String(hdr.grade)), `grade ${hdr.grade}`);
check('version disclosure reported', (hdr.disclosure || []).some(d => d.header === 'x-powered-by'));

const ci = await run('content_intel');
check('internal hostname extracted',
  (ci.categories?.internal_hosts || []).some(h => /corp\.internal$/.test(h)));

stop();
if (fails.length) {
  console.log(`\n${R}${fails.length} check(s) failed${X}`);
  process.exit(1);
}
console.log(`\n${G}every planted leak is still found${X}`);
