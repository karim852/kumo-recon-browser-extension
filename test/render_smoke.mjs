/*
   Execute every renderer.

   renderModule() wraps each renderer in try/catch, so a crash does not hang
   the card -- it quietly prints "render failed" instead. That is still a bug,
   and it is invisible unless something runs the renderers with real data. So
   this does, against a populated payload, an error dict and an empty object,
   and treats "render failed" as a failure rather than a pass.

       node test/render_smoke.mjs
*/
import { MODULE_KEYS } from '../src/engine/registry.js';
import { renderModule } from '../src/render.js';

const G = '\x1b[92m', R = '\x1b[91m', D = '\x1b[90m', B = '\x1b[1m', X = '\x1b[0m';
const fails = [];

/* Populated payloads for the modules whose shape matters most. Anything not
   listed still gets the error and empty cases, which is where crashes hide. */
const PAYLOADS = {
  cms: {
    cms: 'wordpress', cms_name: 'WordPress', confidence: 'high', detection_score: 12,
    signals: ['generator meta', 'wp-content asset path'], candidates: { wordpress: 12 },
    platforms: ['WooCommerce', 'WordPress'], addons: ['WooCommerce'], not_deep_scanned: [],
    version: '6.4.2', version_source: '/', paths_probed: 14,
    users: ['admin', 'marc'], plugins: { woocommerce: '8.4.0' }, themes: { astra: '4.6.0' },
    severity_counts: { critical: 1, low: 1 },
    findings: [
      { name: 'WordPress wp-config backup', severity: 'critical', path: '/wp-config.php.bak', confidence: 'confirmed' },
      { name: 'WordPress version disclosed', severity: 'low', path: '/', confidence: 'version-inference' },
    ],
  },
  cms_not_deep: {
    cms: null, confidence: 'none', platforms: ['Magento'], not_deep_scanned: ['Magento'],
    addons: [], findings: [], note: 'Magento identified, but Kumo has no deep checks for it yet.',
  },
  cms_none: {
    cms: null, confidence: 'none', platforms: [], not_deep_scanned: [], addons: [],
    findings: [], candidates: {}, note: 'No CMS identified.',
  },
  panels: {
    domain: 'example.com', cdn_note: '', method: 'passive port discovery, then HTTP confirmation',
    severity_counts: { high: 1 },
    panels: [{ panel: 'cPanel', port: 2083, url: 'https://example.com:2083/cpanel', signals: ['cPanel login title'], version: null, confidence: 'confirmed' }],
    findings: [{ name: 'cPanel control panel reachable', severity: 'high', path: '/cpanel', url: 'https://example.com:2083/cpanel', confidence: 'confirmed' }],
    unconfirmed: [], ports_open: [2083], ports_seen_passive: [2083], unexplained_ports: [],
  },
  panels_unconfirmed: {
    domain: 'example.com', panels: [], findings: [], ports_open: [], ports_seen_passive: [10000],
    unconfirmed: [{ port: 10000, candidates: ['Webmin'], reason: 'port reported open, but the browser could not read a login interface' }],
    cdn_note: '', method: 'passive', unexplained_ports: [],
  },
  panels_none: {
    domain: 'example.com', panels: [], findings: [], unconfirmed: [],
    ports_open: [], ports_seen_passive: [], unexplained_ports: [],
    note: 'No control panel ports seen open on this host.',
  },
};

const check = (label, ok, detail = '') => {
  if (!ok) fails.push(label);
  console.log(`  ${ok ? G + 'ok  ' + X : R + 'FAIL' + X} ${label}`
    + (detail ? `  ${D}${detail}${X}` : ''));
};

console.log(`${B}every renderer, with data / error / empty${X}  `
  + `${D}(${MODULE_KEYS.length} modules)${X}\n`);

for (const key of MODULE_KEYS) {
  const cases = [
    ['error', { error: 'Module timed out after 60s' }],
    ['empty', {}],
  ];
  if (PAYLOADS[key]) cases.unshift(['data', PAYLOADS[key]]);
  const notes = [];
  let ok = true;
  for (const [name, data] of cases) {
    let out;
    try { out = renderModule(key, data); }
    catch (e) { ok = false; notes.push(`${name}: threw ${e.message}`); continue; }
    if (!out || typeof out.html !== 'string') { ok = false; notes.push(`${name}: no html`); continue; }
    if (out.html.includes('render failed')) { ok = false; notes.push(`${name}: render failed`); continue; }
    notes.push(`${name}=${out.html.length}`);
  }
  check(key.padEnd(16), ok, notes.join(', '));
}

/* the payload variants that exercise specific branches */
console.log(`\n${B}branches that must not say the wrong thing${X}`);
const cmsNotDeep = renderModule('cms', PAYLOADS.cms_not_deep);
check('a platform with no deep checks names the platform',
  cmsNotDeep.html.includes('Magento'), cmsNotDeep.sub);
check('...and does NOT claim no CMS was identified',
  !cmsNotDeep.html.includes('No CMS identified'));
const cmsNone = renderModule('cms', PAYLOADS.cms_none);
check('a genuinely empty result does say no CMS',
  cmsNone.html.includes('No CMS identified'));
const unconf = renderModule('panels', PAYLOADS.panels_unconfirmed);
check('an open-but-unconfirmed port is not presented as a panel',
  unconf.html.includes('not confirmed') && !unconf.html.includes('reachable'),
  unconf.sub);
const pNone = renderModule('panels', PAYLOADS.panels_none);
check('no panel ports open renders the note',
  pNone.html.includes('No control panel ports'));

console.log();
if (fails.length) {
  console.log(`${R}${fails.length} failure(s)${X}`);
  for (const f of fails) console.log('  -', f.trim());
  process.exit(1);
}
console.log(`${G}no card can crash, hang, or claim the wrong thing${X}`);
