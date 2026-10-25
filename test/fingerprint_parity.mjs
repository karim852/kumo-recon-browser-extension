/*
   The fingerprint table must not read prose as evidence.

   Same guard as test_cms.py in the main repo: every brand in the table,
   written the way its own marketing writes it, plus the headers a technical
   article quotes. None of it is installed software, so nothing may fingerprint.

       node test/fingerprint_parity.mjs
*/
import { DATA } from '../src/engine/data/tables.js';

const G = '\x1b[92m', R = '\x1b[91m', D = '\x1b[90m', B = '\x1b[1m', X = '\x1b[0m';
const fails = [];
const check = (label, ok, detail = '') => {
  if (!ok) fails.push(label);
  console.log(`  ${ok ? G + 'ok  ' + X : R + 'FAIL' + X} ${label}`
    + (detail ? `  ${D}${detail}${X}` : ''));
};

/* the same scoped matcher the whatweb module uses */
const hit = (pat, body, headerBlob) => {
  let src = pat, target = headerBlob + '\n' + body;
  if (Array.isArray(pat)) { src = pat[1]; target = pat[0] === 'h' ? headerBlob : body; }
  try { return new RegExp(src, 'i').test(target); } catch { return false; }
};

const fingerprint = (body, headerBlob) => {
  const out = [];
  for (const [cat, sigs] of Object.entries(DATA.WHATWEB_SIGNATURES)) {
    for (const [name, pats] of Object.entries(sigs)) {
      for (const p of (Array.isArray(pats) ? pats : [pats])) {
        if (hit(p, body, headerBlob)) { out.push(`${cat}/${name}`); break; }
      }
    }
  }
  return out;
};

const names = [...new Set([
  ...Object.keys(DATA.WW_CMS_SIGS || {}), ...Object.keys(DATA.WW_ECOM_SIGS || {}),
  ...Object.values(DATA.WHATWEB_SIGNATURES).flatMap(s => Object.keys(s)),
])];

console.log(`${B}prose must not fingerprint${X}  ${D}(${names.length} brands in the table)${X}\n`);

const prose = '<html><head><title>Platform roundup</title></head><body>'
  + '<h1>Every platform compared</h1><p>'
  + names.map(n => `${n}! is worth a look, and ${n} keeps improving`).join('. ')
  + '.</p><p>Debugging tip: check the <code>cf-ray</code>, <code>x-sucuri-id</code> '
  + 'and <code>X-Powered-By: Express</code> headers, and the <code>incap_ses</code> '
  + 'cookie. We also cover settings.php and configuration.php hardening.</p></body></html>';

const leaked = fingerprint(prose, '');
check(`all ${names.length} brands named in body prose fingerprint nothing`,
  leaked.length === 0, leaked.length ? `leaked=${leaked.join(', ')}` : '');

const leakedH = fingerprint('', 'X-Note: ' + names.join(' '));
check('brand names in a header value fingerprint nothing',
  leakedH.length === 0, leakedH.length ? `leaked=${leakedH.join(', ')}` : '');

console.log(`\n${B}real evidence still fingerprints${X}`);
const wp = fingerprint(
  '<link href="/wp-content/themes/astra/style.css"><script src="/wp-includes/js/wp-embed.min.js?ver=6.4.2">',
  'Server: nginx');
check('WordPress asset paths detected', wp.some(x => x.includes('WordPress')), wp.join(', '));

const cf = fingerprint('<html><body>hello</body></html>', 'cf-ray: 8a1b2c3d4e5f-CDG');
check('Cloudflare detected from its header', cf.some(x => x.includes('Cloudflare')), cf.join(', '));

const cfBody = fingerprint('<p>we use cloudflare and the cf-ray header</p>', 'Server: nginx');
check('Cloudflare NOT detected from the same text in the body',
  !cfBody.some(x => x.includes('Cloudflare')), cfBody.join(', ') || 'nothing');

console.log();
if (fails.length) {
  console.log(`${R}${fails.length} failure(s)${X}`);
  for (const f of fails) console.log('  -', f);
  process.exit(1);
}
console.log(`${G}signatures prove software by structure and headers, never by a `
  + `product name in the page${X}`);
