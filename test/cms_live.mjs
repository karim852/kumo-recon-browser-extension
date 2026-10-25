/*
   Run the ported CMS module against the main repo's CMS lab.

   Rendering cleanly is not evidence the port works. This points the real
   module at the real fixtures -- actual HTTP, actual headers -- and checks it
   reaches the same conclusions engine.py's test_cms.py does, decoys included.

       python3 ../kumo-domain-recon-tool/cmslab.py &     (serves the fixtures)
       NODE_TLS_REJECT_UNAUTHORIZED=0 node test/cms_live.mjs

   The lab's certificate is self-signed, hence the flag -- a real browser
   cannot bypass that, which is a genuine limit of the panel module and the
   reason it leans on passive discovery.
*/
import { cms } from '../src/engine/mod-cms.js';

const G = '\x1b[92m', R = '\x1b[91m', D = '\x1b[90m', B = '\x1b[1m', X = '\x1b[0m';
const fails = [];
const check = (label, ok, detail = '') => {
  if (!ok) fails.push(label);
  console.log(`  ${ok ? G + 'ok  ' + X : R + 'FAIL' + X} ${label}`
    + (detail ? `  ${D}${detail}${X}` : ''));
};

const EXPECT = {
  'wp.cmstest': 'wordpress',
  'joomla.cmstest': 'joomla',
  'drupal.cmstest': 'drupal',
  'blog.cmstest': null,
  'plain.cmstest': null,
  'magento.cmstest': null,
};

console.log(`${B}the ported CMS module against the real lab${X}\n`);
const out = {};
for (const [host, want] of Object.entries(EXPECT)) {
  const r = await cms(host);
  out[host] = r;
  if (r.error) { check(`${host.padEnd(16)} -> error`, false, r.error); continue; }
  check(`${host.padEnd(16)} -> ${r.cms || 'none'}`, r.cms === want,
    `expected ${want || 'none'}, score=${r.detection_score}`);
}

console.log(`\n${B}the decoys must stay silent${X}`);
check('a blog writing ABOUT all three identifies none', !out['blog.cmstest']?.cms);
check('...and fingerprints no platform either',
  !(out['blog.cmstest']?.platforms || []).length,
  JSON.stringify(out['blog.cmstest']?.platforms));
check('...and probes no CMS paths', !out['blog.cmstest']?.paths_probed);
check('an ordinary site identifies none', !out['plain.cmstest']?.cms);

console.log(`\n${B}versions and findings${X}`);
check('WordPress version read', out['wp.cmstest']?.version === '6.4.2',
  out['wp.cmstest']?.version);
check('Joomla version read', out['joomla.cmstest']?.version === '4.2.7',
  out['joomla.cmstest']?.version);
check('Drupal version read', out['drupal.cmstest']?.version === '9.5.11',
  out['drupal.cmstest']?.version);
const wpf = (out['wp.cmstest']?.findings || []).map(f => f.name).join(' | ');
check('wp-config backup found', /wp-config backup/i.test(wpf), wpf.slice(0, 70));
check('version finding marked as inference, not proof',
  (out['wp.cmstest']?.findings || []).filter(f => /version disclosed/i.test(f.name))
    .every(f => f.confidence === 'version-inference'));
check('no WordPress path probed on the Drupal site',
  !(out['drupal.cmstest']?.findings || []).some(f => /wp-/.test(f.path || '')));

console.log(`\n${B}platform fingerprinting${X}`);
check('WordPress corroborated by the fingerprint table',
  out['wp.cmstest']?.corroborated_by === 'platform fingerprint',
  JSON.stringify(out['wp.cmstest']?.platforms));
check('WooCommerce listed as an add-on, not a rival platform',
  JSON.stringify(out['wp.cmstest']?.addons) === '["WooCommerce"]'
  && !(out['wp.cmstest']?.not_deep_scanned || []).length);
check('Magento storefront fingerprinted',
  JSON.stringify(out['magento.cmstest']?.platforms) === '["Magento"]',
  JSON.stringify(out['magento.cmstest']?.platforms));
check('Magento reported as having no deep checks',
  JSON.stringify(out['magento.cmstest']?.not_deep_scanned) === '["Magento"]');
check('...with a note instead of a blank result',
  /no deep checks/i.test(out['magento.cmstest']?.note || ''),
  out['magento.cmstest']?.note);

console.log(`\n${B}WordPress enumeration${X}`);
check('users enumerated via the REST API',
  (out['wp.cmstest']?.users || []).length >= 2,
  JSON.stringify(out['wp.cmstest']?.users));
check('plugins read from the homepage',
  Object.keys(out['wp.cmstest']?.plugins || {}).length >= 2,
  JSON.stringify(out['wp.cmstest']?.plugins));

console.log();
if (fails.length) {
  console.log(`${R}${fails.length} failure(s)${X}`);
  for (const f of fails) console.log('  -', f.trim());
  process.exit(1);
}
console.log(`${G}the browser port reaches the same conclusions as engine.py on the `
  + `same fixtures${X}`);
