/* ════════════════════════════════════════════════════════════
   The module registry — the browser-side equivalent of
   engine.ALL_MODULES. Order matches engine.py.

   `ports` is here but PASSIVE: a browser cannot open a TCP
   socket, so it reports what Shodan last observed rather than
   probing. Guessing from fetch timings was the alternative, and
   a "closed" you cannot trust is worse than an honest "not seen".
   ════════════════════════════════════════════════════════════ */

import * as I from './mod-intel.js';
import * as H from './mod-http.js';
import * as C from './mod-cms.js';

const M = (key, description, icon, run) => ({ key, description, icon, run });

export const MODULES = [
  M('screenshot', 'Page Identity & Metadata', '🖼', ({ domain, signal }) => H.screenshot(domain, signal)),
  M('dns', 'DNS Records + Email Security', '🌐', ({ domain, signal }) => I.dns(domain, signal)),
  M('geo', 'IP Geolocation & ASN', '📍', ({ domain, signal }) => I.geo(domain, signal)),
  M('whois', 'WHOIS / RDAP Registration', '📋', ({ domain, signal }) => I.whois(domain, signal)),
  M('ssl', 'Certificates (CT logs)', '🔒', ({ domain, signal }) => I.ssl(domain, signal)),
  M('headers', 'HTTP Security Headers', '🛡', ({ domain, signal }) => H.headers(domain, signal)),
  M('wafw00f', 'WAF Detection', '🧱', ({ domain, signal }) => H.wafw00f(domain, signal)),
  M('ports', 'Open Ports (passive, via Shodan)', '🔌', ({ domain, signal }) => I.ports(domain, signal)),
  M('whatweb', 'Deep Tech Detection', '🧬', ({ domain, signal }) => H.whatweb(domain, signal)),
  M('robots', 'Robots/Security/Sitemap', '🤖', ({ domain, signal }) => H.robots(domain, signal)),
  M('endpoints', 'Sensitive Endpoints (141 paths)', '📂', ({ domain, signal }) => H.endpoints(domain, signal)),
  M('nuclei', 'Vulnerability Scanner (420 checks)', '☣', ({ domain, signal }) => H.nuclei(domain, signal)),
  M('shodan', 'Shodan InternetDB + CVEs', '🛰', ({ domain, signal }) => I.shodan(domain, signal)),
  M('censys', 'Censys Hosts + Certificates', '📡', ({ domain, signal }) => I.censys(domain, signal)),
  M('subdomains', 'Subdomain Discovery', '🕸', ({ domain, signal }) => I.subdomains(domain, signal)),
  M('brute', 'Subdomain Brute Force', '🔨', ({ domain, signal }) => I.brute(domain, signal)),
  M('wayback', 'Wayback Machine Archives', '🕰', ({ domain, signal }) => I.wayback(domain, signal)),
  M('email_harvest', 'Email Harvester', '✉', ({ domain, signal }) => I.emailHarvest(domain, signal)),
  M('breachintel', 'Breach & Credential Intelligence', '🩸', ({ domain, signal }) => I.breachIntel(domain, signal)),
  M('favicon', 'Favicon Hash Fingerprinting', '🎯', ({ domain, signal }) => H.favicon(domain, signal)),
  M('cloud_buckets', 'Cloud Bucket Finder', '🪣', ({ domain, signal }) => H.cloudBuckets(domain, signal)),
  M('js_secrets', 'JS Secret Scanner', '🔑', ({ domain, signal }) => H.jsSecrets(domain, signal)),
  M('content_intel', 'Content Intel (JS/HTML extractor)', '🧠', ({ domain, signal }) => H.contentIntel(domain, signal)),
  M('http_inspect', 'HTTP Inspector', '📶', ({ domain, signal }) => H.httpInspect(domain, signal)),
  M('api_fuzzer', 'API Endpoint Fuzzer', '⚙', ({ domain, signal }) => H.apiFuzzer(domain, signal)),
  M('cms', 'CMS Deep Scan (WP/Joomla/Drupal)', '🧱', ({ domain, signal }) => C.cms(domain, signal)),
  // PASSIVE, like `ports`: a page cannot open a TCP socket, and panels on
  // 2083/8443/10000 almost always present a self-signed certificate that
  // fetch() refuses. Shodan supplies which panel ports are open; HTTP confirms
  // the interface where it can, and says so when it cannot.
  M('panels', 'Hosting Control Panels (passive + HTTP)', '🎛', ({ domain, signal }) => C.panels(domain, signal)),
];

export const MODULE_KEYS = MODULES.map(m => m.key);
export const ICONS = Object.fromEntries(MODULES.map(m => [m.key, m.icon]));
export const DESCS = Object.fromEntries(MODULES.map(m => [m.key, m.description]));

/* A tight set that returns in a few seconds — the popup default. */
export const QUICK_SET = [
  'dns', 'geo', 'whois', 'ssl', 'headers', 'wafw00f',
  'whatweb', 'robots', 'http_inspect', 'favicon', 'screenshot', 'ports',
];

export const SHORT = {
  panels: 'panels', cms: 'cms',
  screenshot: 'identity', email_harvest: 'emails', breachintel: 'breach',
  cloud_buckets: 'buckets', js_secrets: 'js-keys', content_intel: 'content',
  http_inspect: 'http', api_fuzzer: 'api-fuzz', subdomains: 'subs',
  endpoints: 'paths', nuclei: 'vulns', wafw00f: 'waf', ssl: 'certs',
};
export const shortName = k => SHORT[k] || k;
