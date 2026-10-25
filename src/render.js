/* ════════════════════════════════════════════════════════════
   Card renderers — one per module, condensed for a 420px panel.
   Every renderer returns an HTML string for the card body and
   may set a one-line summary shown in the card header.
   ════════════════════════════════════════════════════════════ */

import { SEV_COLOR, sevKey, count, cvssSeverity } from './sev.js';

/* ── helpers ──────────────────────────────────────────────── */
export const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const A = (url, label) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label || url)}</a>`;
const kv = (k, v) => v === undefined || v === null || v === '' ? ''
  : `<div class="kv"><dt>${esc(k)}</dt><dd>${v}</dd></div>`;
const bytes = n => {
  n = Number(n); if (!n && n !== 0) return '';
  if (n < 1024) return `${n}B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / 1048576).toFixed(1)}M`;
};
const empty = m => `<div class="empty">${esc(m)}</div>`;
/* A stat is always a scalar: if a module hands back the list rather than its
   length (the engine does both), show the length. */
const stat = (val, lbl, color) => {
  const v = Array.isArray(val) ? val.length : (val && typeof val === 'object' ? Object.keys(val).length : val);
  return `<div class="stat"><b style="color:${color || 'var(--text)'}">${esc(v)}</b><span>${esc(lbl)}</span></div>`;
};
const stats = inner => `<div class="stats">${inner}</div>`;

/* A severity-sorted, capped finding list with a "show the rest" tail. */
const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
let UNCAPPED = false;   // flipped by renderModule(key, data, true)
function findings(list, cap, mapper) {
  if (UNCAPPED) cap = Infinity;
  const items = (list || []).slice().sort(
    (a, b) => (RANK[sevKey(a.severity)] ?? 9) - (RANK[sevKey(b.severity)] ?? 9));
  if (!items.length) return '';
  const head = items.slice(0, cap).map(f => {
    const s = sevKey(f.severity);
    const { title, sub } = mapper(f);
    return `<div class="row ${s === 'critical' ? 'crit' : s}">
      <span class="sev-lbl" style="color:${SEV_COLOR[s]}">${s.slice(0, 4).toUpperCase()}</span>
      <div class="row-main"><div class="row-t">${title}</div>${sub ? `<div class="row-s">${sub}</div>` : ''}</div>
    </div>`;
  }).join('');
  const rest = items.length - cap;
  return head + (rest > 0 ? `<div class="more" data-expand>+ ${rest} more</div>` : '');
}

/* severity counts → chip row */
function sevChips(counts) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const parts = order.filter(k => Number(counts && counts[k]) > 0)
    .map(k => `<span class="badge" style="color:${SEV_COLOR[k]};border-color:${SEV_COLOR[k]}33">${counts[k]} ${k}</span>`);
  return parts.length ? `<div style="margin-bottom:7px;display:flex;gap:4px;flex-wrap:wrap">${parts.join('')}</div>` : '';
}

/* Modules return either plain strings or small objects ({path,…});
   flatten both to a label so no tag ever prints [object Object]. */
const label = x => {
  if (x == null) return '';
  if (typeof x !== 'object') return String(x);
  return String(x.path ?? x.name ?? x.subdomain ?? x.host ?? x.url ?? x.id ??
                x.cve ?? x.value ?? x.email ?? x.record ?? JSON.stringify(x));
};
// RDAP and the other third-party APIs are not always shape-correct: a server
// that answers "status": "active" where the spec says a list would otherwise
// crash the renderer, and the card prints "render failed" instead of the data.
const list2 = (arr, cls) => (Array.isArray(arr) ? arr : arr == null ? [] : [arr])
  .map(x => `<span class="${cls || 'tag'}">${esc(label(x))}</span>`).join('');

/* ════════════════════════════════════════════════════════════
   Renderers.  Each: (d) => { html, sub }
   ════════════════════════════════════════════════════════════ */
const R = {};

R.dns = d => {
  const rec = d.records || {}, ips = d.ips || {}, es = d.email_security || {};
  const mark = v => {
    const ok = v === true || (v && (v.found || v.present || v.valid));
    const txt = typeof v === 'string' ? v : (v && (v.record || v.policy)) || '';
    return `<span class="badge ${ok ? 'b-ok' : 'b-fail'}">${ok ? '✓' : '✗'}</span>${txt ? ` <span class="c-dim mono" style="font-size:9px">${esc(String(txt).slice(0, 48))}</span>` : ''}`;
  };
  let h = '';
  h += kv('A', list2(ips.v4 || rec.A, 'badge') || '<span class="c-dim">—</span>');
  if ((ips.v6 || rec.AAAA || []).length) h += kv('AAAA', list2(ips.v6 || rec.AAAA, 'badge'));
  if ((rec.MX || []).length) h += kv('MX', list2(rec.MX.slice(0, 3)));
  if ((rec.NS || []).length) h += kv('NS', list2(rec.NS.slice(0, 3)));
  if ((rec.CAA || []).length) h += kv('CAA', list2(rec.CAA.slice(0, 2)));
  h += `<div style="margin-top:6px;border-top:1px solid var(--border);padding-top:6px">
    ${kv('SPF', mark(es.spf))}${kv('DMARC', mark(es.dmarc))}${kv('DKIM', mark(es.dkim))}</div>`;
  const nip = (ips.v4 || rec.A || []).length;
  return { html: h, sub: `${nip} ip${nip === 1 ? '' : 's'}` };
};

R.geo = d => ({
  html: kv('IP', `<span class="c-cyan">${esc(d.ip)}</span>`) +
        kv('Location', `${d.flag ? d.flag + ' ' : ''}${esc([d.city, d.region, d.country].filter(Boolean).join(', '))}`) +
        kv('ISP', esc(d.isp)) + kv('ASN', esc(d.asn)) +
        kv('Hostname', esc(d.hostname)) + kv('Timezone', esc(d.timezone)) +
        (d.is_hosting ? kv('Type', '<span class="badge b-info">hosting / datacenter</span>') : ''),
  sub: d.country_code || d.country || '',
});

R.whois = d => {
  // Registry has no RDAP: that is information, not a failure.
  if (d.rdap_available === false) {
    return {
      html: `<div class="empty" style="margin-bottom:7px">${esc(d.note || '')}</div>` +
        Object.entries(d.links || {}).map(([k, v]) => kv(k, A(v, 'look up \u2197'))).join(''),
      sub: 'no rdap',
    };
  }
  const dd = Number(d.days_until_expiry);
  const col = dd < 0 ? 'var(--red)' : dd < 30 ? 'var(--orange)' : 'var(--green)';
  return {
    html: kv('Registered', esc(d.registration)) +
      kv('Expires', `${esc(d.expiration)} ${!Number.isNaN(dd) ? `<span style="color:${col}">(${dd}d)</span>` : ''}`) +
      kv('Updated', esc(d.last_changed)) +
      kv('Nameservers', list2((d.nameservers || []).slice(0, 4))) +
      kv('Status', list2((d.status || []).slice(0, 4))) +
      kv('Entities', (d.entities || []).map(e => `${esc(e.role)}: ${esc(e.name)}`).join('<br>')),
    sub: Number.isNaN(dd) ? '' : `${dd}d left`,
  };
};

R.ssl = d => {
  const dl = Number(d.days_left);
  const col = dl < 0 ? 'var(--red)' : dl < 30 ? 'var(--orange)' : 'var(--green)';
  const weak = /TLSv1(\.[01])?$/.test(String(d.protocol || ''));
  return {
    html: kv('Subject', esc(d.common_name)) + kv('Issuer', esc(d.issuer)) +
      kv('Valid until', `${esc(d.valid_until)} <span style="color:${col}">(${dl}d)</span>`) +
      kv('Protocol', `<span class="badge ${weak ? 'b-fail' : 'b-ok'}">${esc(d.protocol)}</span>`) +
      kv('Cipher', `${esc(d.cipher)} ${d.cipher_bits ? `<span class="c-dim">${d.cipher_bits}b</span>` : ''}`) +
      ((d.sans || []).length ? kv(`SANs (${d.sans.length})`, list2(d.sans.slice(0, 8))) : ''),
    sub: d.protocol || '',
  };
};

R.headers = d => {
  const g = String(d.grade || '?');
  const col = /^A/.test(g) ? 'var(--green)' : /^B/.test(g) ? 'var(--cyan)'
    : /^C/.test(g) ? 'var(--yellow)' : /^D/.test(g) ? 'var(--orange)' : 'var(--red)';
  let h = `<div class="grade"><div class="grade-c" style="color:${col}">${esc(g)}</div>
    <div><div class="mono" style="font-size:10px">score <b style="color:${col}">${esc(d.score)}</b>/100</div>
    <div class="mono c-dim" style="font-size:9px">HTTP ${esc(d.status_code)} · ${esc(d.server || 'server hidden')}</div></div></div>`;
  (d.headers || []).forEach(x => {
    h += `<div class="kv"><dt style="min-width:0;flex:1;color:${x.present ? 'var(--text2)' : 'var(--text3)'}">${esc(x.header)}</dt>
      <dd style="flex:0 0 auto"><span class="badge ${x.present ? 'b-ok' : 'b-fail'}">${x.present ? '✓' : 'missing'}</span></dd></div>`;
  });
  if ((d.disclosure || []).length) {
    h += `<div style="margin-top:6px;border-top:1px solid var(--border);padding-top:6px">
      <div class="mono c-dim" style="font-size:8.5px;margin-bottom:3px">VERSION DISCLOSURE</div>`;
    d.disclosure.forEach(x => { h += kv(x.header, `<span class="c-orange">${esc(x.value)}</span>`); });
    h += '</div>';
  }
  return { html: h, sub: `grade ${g}` };
};

R.wafw00f = d => {
  const det = d.detected || [];
  if (!det.length) return { html: empty('No WAF fingerprinted on the edge.'), sub: 'none' };
  return {
    html: det.map(w => kv(w.waf, `${esc(w.vendor || '')} <span class="badge b-info">${esc(w.confidence)}</span>
      <div class="row-s">${esc(w.evidence || '')}</div>`)).join(''),
    sub: det[0].waf,
  };
};

R.ports = d => {
  const open = d.open || [];
  const passive = !!d.passive;
  if (!open.length) {
    return {
      html: empty(passive
        ? 'Shodan has no record of open ports on these IPs.'
        : `No open ports among ${d.total_scanned || 0} probed.`),
      sub: passive ? 'none seen' : '0 open',
    };
  }
  const col = r => {
    r = String(r || '').toLowerCase();
    return r.includes('crit') ? 'var(--red)' : r.includes('high') ? 'var(--orange)'
      : r.includes('med') ? 'var(--yellow)' : 'var(--green)';
  };
  const banner = passive
    ? `<div class="mono" style="font-size:8.5px;color:var(--text3);background:var(--bg3);
         border:1px solid var(--border);border-radius:5px;padding:5px 7px;margin-bottom:6px">
         ⓘ Observed by ${esc(d.source || 'Shodan')} — not probed from your browser.
         A port missing here means <b>not seen</b>, not closed.</div>`
    : '';
  return {
    html: banner + open.map(p => `<div class="row" style="border-left-color:${col(p.risk)}">
      <span class="sev-lbl mono" style="color:${col(p.risk)};min-width:28px">${esc(p.port)}</span>
      <div class="row-main"><div class="row-t">${esc(p.service)}${p.version ? ` <span class="c-dim mono" style="font-size:9px">${esc(p.version)}</span>` : ''}</div>
      ${p.banner ? `<div class="row-s">${esc(String(p.banner).slice(0, 110))}</div>` : ''}</div></div>`).join(''),
    sub: passive ? `${open.length} seen` : `${open.length}/${d.total_scanned || '?'} open`,
  };
};

R.whatweb = d => {
  const det = d.detected || {};
  const keys = Object.keys(det);
  if (!keys.length) return { html: empty('Nothing fingerprinted.'), sub: '' };
  return {
    html: keys.map(cat => kv(cat, list2([].concat(det[cat] || []).map(
      v => typeof v === 'object' ? [v.name, v.version].filter(Boolean).join(' ') : v)))).join(''),
    sub: `${d.total_detected || keys.length} tech`,
  };
};

R.robots = d => {
  const rb = d.robots || {}, st = d.security_txt || {};
  // Paths robots.txt hides are often the interesting ones — flag them.
  const paths = (rb.disallowed || []).slice(0, 12).map(p =>
    `<span class="tag" style="${p && p.sensitive ? 'color:var(--orange);border-color:rgba(255,166,87,.35)' : ''}">${esc(label(p))}</span>`).join('');
  return {
    html: kv('robots.txt', rb.count ? `<span class="badge b-info">${rb.count} rules</span>` : '<span class="badge">absent</span>') +
      (paths ? kv('Disallowed', paths) : '') +
      kv('Sitemaps', (d.sitemaps || []).length ? (d.sitemaps || []).map(s => A(s, s.replace(/^https?:\/\/[^/]+/, ''))).join('<br>') : '<span class="c-dim">—</span>') +
      kv('security.txt', `<span class="badge ${st.found ? 'b-ok' : ''}">${st.found ? 'present' : 'absent'}</span>`),
    sub: `${(rb.disallowed || []).length} disallow`,
  };
};

const findingCard = (d, label) => {
  const f = d.findings || [];
  if (!f.length) return { html: empty(`Nothing found across ${d.total_probed || d.total || 0} ${label}.`), sub: 'clean' };
  return {
    html: sevChips(d.severity_counts) + findings(f, 6, x => ({
      title: esc(x.name),
      sub: `${esc(x.path)} <span class="c-dim">[${esc(x.status)}${x.size ? ' · ' + bytes(x.size) : ''}]</span>`,
    })),
    sub: `${d.total_found ?? f.length} found`,
  };
};
R.endpoints = d => findingCard(d, 'paths');
R.nuclei = d => {
  if (d.nuclei_installed === false && !(d.findings || []).length) {
    return { html: empty('Built-in checks only — nuclei binary not installed.'), sub: 'builtin' };
  }
  return findingCard(d, 'checks');
};

R.cms = d => {
  // A platform can be identified without deep checks existing for it. "No CMS"
  // would be wrong there, and an empty card reads as a clean result.
  if (!d.cms) {
    const nd = d.not_deep_scanned || [];
    if (nd.length) {
      return {
        html: kv('Platform', list2(nd, 'badge'))
          + `<div class="c-warn" style="font-size:11px;margin-top:6px">No deep checks for `
          + `${nd.length > 1 ? 'these platforms' : 'this platform'} yet</div>`
          + `<div class="c-dim" style="font-size:10px;margin-top:3px">Deep checks cover `
          + `WordPress, Joomla and Drupal.</div>`,
        sub: esc(nd[0]),
      };
    }
    return { html: empty(d.note || 'No CMS identified.'), sub: 'none' };
  }

  let h = kv('CMS', `<span class="c-cyan" style="font-weight:700">${esc(d.cms_name || d.cms)}</span>`
    + ` <span class="badge ${d.confidence === 'high' ? 'b-ok' : 'b-info'}">${esc(d.confidence)}</span>`);
  if (d.version) h += kv('Version', `<span class="c-yellow mono">${esc(d.version)}</span>`
    + ` <span class="c-dim" style="font-size:9px">from ${esc(d.version_source || '')}</span>`);
  if ((d.signals || []).length) h += kv('Detected by',
    `<span class="c-dim" style="font-size:10px">${esc(d.signals.join(' · '))}</span>`);
  if ((d.addons || []).length) h += kv('Also running', list2(d.addons, 'badge'));
  if (d.platform_conflict) h += kv('Note',
    `<span class="c-warn" style="font-size:10px">${esc(d.platform_conflict)}</span>`);
  if ((d.users || []).length) h += kv('Users', list2(d.users.slice(0, 8), 'tag'));
  const plug = Object.keys(d.plugins || {});
  if (plug.length) h += kv('Plugins', list2(
    plug.slice(0, 8).map(k => d.plugins[k] ? `${k} ${d.plugins[k]}` : k), 'tag'));
  const th = Object.keys(d.themes || {});
  if (th.length) h += kv('Themes', list2(
    th.slice(0, 4).map(k => d.themes[k] ? `${k} ${d.themes[k]}` : k), 'tag'));

  const f = d.findings || [];
  if (f.length) {
    h += sevChips(d.severity_counts) + findings(f, 6, x => ({
      title: esc(x.name),
      sub: `${esc(x.path || '')}${x.confidence === 'version-inference'
        ? ' <span class="c-dim">[inferred]</span>' : ''}`,
    }));
  }
  h += `<div class="c-dim" style="font-size:9px;margin-top:6px">`
    + `${d.paths_probed || 0} ${esc(d.cms)} path(s) probed</div>`;
  return { html: h, sub: `${esc(d.cms_name || d.cms)}${d.version ? ' ' + esc(d.version) : ''}` };
};

R.panels = d => {
  let h = '';
  const p = d.panels || [], un = d.unconfirmed || [];
  if (d.cdn_note) h += `<div class="c-dim" style="font-size:10px;margin-bottom:5px">`
    + `${esc(d.cdn_note)}</div>`;
  if (p.length) {
    h += sevChips(d.severity_counts) + findings(d.findings || [], 6, x => ({
      title: esc(x.name),
      sub: `${esc(x.url || '')}`,
    }));
  }
  if (un.length) {
    // Shodan saw the port open; the browser could not read it. Say which, and
    // never present it as a confirmed panel.
    h += kv('Port open, not confirmed', list2(un.map(u => `:${u.port}`), 'badge'))
      + `<div class="c-dim" style="font-size:10px;margin-top:3px">`
      + `${esc(un[0].reason)}</div>`;
  }
  if (!p.length && !un.length) {
    return { html: empty(d.note || 'No control panel ports seen open.'), sub: 'none' };
  }
  h += `<div class="c-dim" style="font-size:9px;margin-top:6px">${esc(d.method || '')}</div>`;
  return {
    html: h,
    sub: p.length ? `${p.length} panel${p.length === 1 ? '' : 's'}` : `${un.length} unconfirmed`,
  };
};

R.shodan = d => {
  const s = d.summary || {}, ips = d.ips || {};
  const nCrit = count(s.critical_cves);
  const nCve = count(s.total_cves) ||
    Object.values(ips).reduce((n, v) => n + (v.cves || v.vulns || []).length, 0);

  let h = stats(
    stat(count(s.total_ports) || Object.values(ips).reduce((n, v) => n + (v.ports || []).length, 0), 'ports', 'var(--cyan)') +
    stat(nCve, 'cves', nCve ? 'var(--yellow)' : 'var(--text3)') +
    stat(nCrit, 'critical', nCrit ? 'var(--red)' : 'var(--text3)'));

  for (const [ip, v] of Object.entries(ips).slice(0, 4)) {
    h += `<div style="margin-top:6px"><div class="mono" style="font-size:9.5px;color:var(--cyan)">${esc(ip)}
      ${v.os ? `<span class="badge">${esc(v.os)}</span>` : ''}${list2(v.tags, 'badge')}</div>
      <div style="margin:3px 0">${list2((v.ports || []).slice(0, 14), 'badge')}</div>`;
    // CVEs carry a CVSS score, not a severity word — colour by band.
    for (const c of (v.cves || v.vulns || []).slice(0, 6)) {
      const sev = cvssSeverity(c && c.cvss);
      h += `<div class="row ${sev === 'critical' ? 'crit' : sev}">
        <span class="sev-lbl mono" style="color:${SEV_COLOR[sev]};min-width:26px">${c.cvss ?? '?'}</span>
        <div class="row-main"><div class="row-t">${esc(c.id || c.cve || '')}</div>
        ${c.summary ? `<div class="row-s">${esc(c.summary)}</div>` : ''}</div></div>`;
    }
    h += '</div>';
  }
  return { html: h, sub: `${nCve} cve${nCve === 1 ? '' : 's'}` };
};

R.censys = d => ({
  html: (d.ct_error ? `<div class="err" style="margin-bottom:6px">\u26a0 ${esc(d.ct_error)}</div>` : '') +
    kv('IPs', list2(d.ips, 'badge')) +
    (d.certificates || []).map(c => kv(c.subject, `${esc(c.issuer)}<div class="row-s">${esc(c.validity)}</div>`)).join('') +
    Object.entries(d.links || {}).map(([k, v]) => kv(k, A(v, 'open ↗'))).join(''),
  sub: `${(d.ips || []).length} host`,
});

const subCard = d => {
  const sens = d.sensitive || [], resolved = d.resolved || [];
  let h = stats(
    stat(d.total ?? resolved.length, 'found', 'var(--cyan)') +
    stat(d.alive_count ?? resolved.length, 'alive', 'var(--green)') +
    stat(sens.length, 'sensitive', sens.length ? 'var(--orange)' : 'var(--text3)'));
  if (sens.length) {
    h += `<div class="mono c-dim" style="font-size:8.5px;margin:4px 0 3px">SENSITIVE HOSTNAMES</div>`;
    h += sens.slice(0, 8).map(s => `<div class="row medium"><div class="row-main">
      <div class="row-t">${esc(s.subdomain || s)}</div>
      ${s.ip ? `<div class="row-s">${esc(s.ip)}</div>` : ''}</div></div>`).join('');
  }
  if ((d.ct_sensitive || []).length) h += kv('CT only', list2(d.ct_sensitive.slice(0, 10)));
  if (resolved.length) h += kv('Resolved', list2(resolved.slice(0, 14).map(r => r.subdomain || r)));
  return { html: h, sub: `${d.total ?? resolved.length}` };
};
R.subdomains = subCard;
R.brute = subCard;

R.wayback = d => ({
  html: stats(stat(d.total ?? 0, 'snapshots', 'var(--cyan)') + stat(d.range || '—', 'range')) +
    (d.snapshot ? kv('Latest', `${A(d.snapshot.url, d.snapshot.timestamp)}`) : '') +
    ((d.interesting || []).length ? `<div class="mono c-dim" style="font-size:8.5px;margin:5px 0 3px">INTERESTING URLS</div>` +
      d.interesting.slice(0, 8).map(u => `<div class="row low"><div class="row-main"><div class="row-s">${A(u, u)}</div></div></div>`).join('') : ''),
  sub: d.range || '',
});

R.email_harvest = d => ({
  html: ((d.emails || []).length
    ? d.emails.map(e => `<span class="tag" style="color:var(--cyan)">${esc(e)}</span>`).join('')
    : empty('No addresses recovered.')) +
    ((d.sources_used || []).length ? `<div class="mono c-dim" style="font-size:8.5px;margin-top:6px">via ${esc(d.sources_used.join(' · '))}</div>` : ''),
  sub: `${(d.emails || []).length} addr`,
});

R.breachintel = d => {
  const s = d.summary || {};
  if (d.reachable === false) {
    return { html: `<div class="err">\u26a0 ${esc(d.error || 'lookup failed')}</div>`, sub: 'unreachable' };
  }
  let h = stats(
    stat(s.total_infostealer_hits ?? 0, 'stealer', (s.total_infostealer_hits ? 'var(--red)' : 'var(--text3)')) +
    stat(s.total_employees_leaked ?? 0, 'employees', 'var(--orange)') +
    stat(s.total_clients_leaked ?? 0, 'clients', 'var(--yellow)') +
    stat(s.total_emails_found ?? 0, 'emails', 'var(--cyan)'));
  (s.critical_findings || []).slice(0, 5).forEach(f => {
    h += `<div class="row crit"><div class="row-main">
      <div class="row-t">${esc(f.type)} <span class="badge">${esc(f.source)}</span></div>
      <div class="row-s">${esc(f.detail)}</div></div></div>`;
  });
  if (d.note) h += `<div class="mono c-dim" style="font-size:8.5px;margin-top:5px">${esc(d.note)}</div>`;
  return { html: h, sub: s.total_infostealer_hits ? `${s.total_infostealer_hits} infected` : 'clean' };
};


R.favicon = d => {
  if (!d.favicon_found) return { html: empty('No favicon served.'), sub: 'none' };
  return {
    html: `<div style="display:flex;gap:9px;align-items:center;margin-bottom:6px">
        <img src="${esc(d.favicon_url)}" alt="" style="width:34px;height:34px;border-radius:6px;object-fit:contain;background:var(--bg3);border:1px solid var(--border)">
        <div><div class="mono" style="font-size:10px">${esc(d.technology || 'unknown stack')}</div>
        <div class="mono c-dim" style="font-size:8.5px">${bytes(d.size_bytes)} · mmh3 ${esc(d.hash_shodan)}</div></div></div>` +
      kv('MD5', `<span style="font-size:9px">${esc(d.hash_md5)}</span>`) +
      Object.entries(d.search_links || {}).map(([k, v]) => kv(k, A(v, 'pivot ↗'))).join(''),
    sub: d.technology || 'hashed',
  };
};

R.cloud_buckets = d => {
  const ex = d.exposed || [];
  if (!ex.length) return { html: empty(`No bucket responded across ${d.checked || 0} permutations.`), sub: 'none' };
  return {
    html: findings(ex, 8, b => ({
      title: `${esc(b.name)} <span class="badge">${esc(b.provider)}</span>`,
      sub: `${A(b.url, b.url)} <span class="c-dim">[${esc(b.status)}${b.files ? ` · ${b.files} files` : ''}]</span>`,
    })),
    sub: `${ex.length} exposed`,
  };
};

R.js_secrets = d => {
  const s = d.secrets || [];
  if (!s.length) return { html: empty(`No secrets in ${(d.js_files || []).length} JS files.`), sub: 'clean' };
  return {
    html: findings(s, 6, x => ({
      title: `${esc(x.type)} <span class="mono c-cyan" style="font-size:9px">${esc(x.value)}</span>`,
      sub: `${esc(x.file)}${x.line ? `<div style="color:var(--text3);margin-top:1px">${esc(String(x.line).slice(0, 90))}</div>` : ''}`,
    })),
    sub: `${s.length} secret${s.length === 1 ? '' : 's'}`,
  };
};

R.content_intel = d => {
  const c = d.counts || {}, cats = d.categories || {};
  let h = stats(Object.entries(c).slice(0, 6)
    .map(([k, v]) => stat(v, k.replace(/_/g, ' '), 'var(--cyan)')).join(''));
  for (const [cat, items] of Object.entries(cats)) {
    if (!(items || []).length) continue;
    h += kv(cat.replace(/_/g, ' '), list2(items.slice(0, 8)));
  }
  return { html: h, sub: `${d.total ?? 0} items` };
};

R.http_inspect = d => {
  const s = d.summary || {}, m = d.methods || {};
  let h = kv('Final', `${A(s.final_url, s.final_url)} <span class="badge b-info">${esc(s.final_status)}</span>`) +
    kv('Hops', esc(s.hops)) + kv('TLS', esc(s.tls));
  if ((d.redirect_chain || []).length > 1) {
    h += `<div class="mono c-dim" style="font-size:8.5px;margin:5px 0 3px">REDIRECT CHAIN</div>`;
    h += d.redirect_chain.map(r => `<div class="row-s">[${esc(r.status)}] ${esc(r.url)}</div>`).join('');
  }
  const danger = new Set(m.dangerous || []);
  h += kv('Methods', list2((m.allowed || []).filter(x => !danger.has(x)), 'badge') +
    [...danger].map(x => `<span class="badge b-fail">${esc(x)}</span>`).join(''));
  (d.cookies || []).forEach(c => {
    const flags = ['secure', 'httponly', 'samesite'].map(f =>
      `<span class="badge ${c[f] ? 'b-ok' : 'b-warn'}">${f}${c[f] && c[f] !== true ? '=' + esc(c[f]) : ''}</span>`).join('');
    h += kv(`🍪 ${c.name}`, flags);
  });
  return { html: h, sub: `${s.final_status ?? ''}` };
};

R.api_fuzzer = d => {
  let h = '';
  if ((d.bases_found || []).length) h += kv('API bases', list2(d.bases_found, 'badge'));
  if (d.graphql) {
    const s = sevKey(d.graphql.severity);
    h += `<div class="row ${s === 'critical' ? 'crit' : s}">
      <span class="sev-lbl" style="color:${SEV_COLOR[s]}">${s.slice(0, 4).toUpperCase()}</span>
      <div class="row-main"><div class="row-t">GraphQL at ${esc(d.graphql.path)}</div>
      <div class="row-s">${esc(d.graphql.detail || '')}</div></div></div>`;
  }
  h += findings(d.specs, 6, x => ({
    title: esc(x.name),
    sub: `${esc(x.path)} <span class="c-dim">[${esc(x.status)} · ${bytes(x.size)}]</span>`,
  }));
  h += findings(d.findings, 6, x => ({ title: esc(x.name || x.path), sub: esc(x.path || '') }));
  return { html: h || empty('No API surface exposed.'), sub: `${d.total ?? 0} hits` };
};

R.screenshot = d => {
  const clean = d.ransomware_status === 'clean';
  const unchecked = /not checked|unknown/i.test(String(d.ransomware_status || ''));
  const hits = Number((d.threat_feeds || {}).hits) || 0;
  const checked = Number((d.threat_feeds || {}).checked) || 0;
  return {
    html: kv('Title', esc(d.title)) + kv('Description', esc(d.description)) +
      kv('URL', d.url ? A(d.url, d.url) : '') + kv('CMS', esc(d.cms)) +
      kv('Ransomware', `<span class="badge ${unchecked ? '' : clean ? 'b-ok' : 'b-fail'}">${esc(d.ransomware_status || 'unknown')}</span>`) +
      (checked ? kv('Threat feeds', `<span class="badge ${hits ? 'b-fail' : 'b-ok'}">${hits} hit${hits === 1 ? '' : 's'} / ${checked} checked</span>`) : '') +
      (d.note ? `<div class="mono c-dim" style="font-size:8.5px;margin-top:5px">${esc(d.note)}</div>` : ''),
    sub: d.cms || '',
  };
};

/* ── generic fallback for anything unmapped ───────────────── */
function generic(d) {
  if (d == null) return { html: empty('No data.'), sub: '' };
  if (typeof d !== 'object') return { html: `<div class="mono">${esc(d)}</div>`, sub: '' };
  let h = '';
  for (const [k, v] of Object.entries(d)) {
    if (k.startsWith('_')) continue;
    if (v == null || v === '' || (Array.isArray(v) && !v.length)) continue;
    if (Array.isArray(v)) {
      h += kv(k, v.every(x => typeof x !== 'object')
        ? list2(v.slice(0, 12))
        : `<span class="badge">${v.length} items</span>`);
    } else if (typeof v === 'object') {
      h += kv(k, `<span class="badge">${Object.keys(v).length} keys</span>`);
    } else {
      h += kv(k, esc(String(v).slice(0, 160)));
    }
  }
  return { html: h || empty('Empty result.'), sub: '' };
}

/* ── public entry point ───────────────────────────────────── */
export function renderModule(key, data, showAll = false) {
  if (!data) return { html: empty('No data.'), sub: '' };
  if (data.error) return { html: `<div class="err">⚠ ${esc(data.error)}</div>`, sub: 'error' };
  UNCAPPED = showAll;
  try {
    return (R[key] || generic)(data);
  } catch (e) {
    return { html: `<div class="err">⚠ render failed: ${esc(e.message)}</div>`, sub: 'error' };
  } finally {
    UNCAPPED = false;
  }
}

/* Plain-text findings digest for the clipboard button. */
export function digest(domain, results) {
  const out = [`KUMO — ${domain}`, '='.repeat(40)];
  for (const [k, d] of Object.entries(results || {})) {
    if (!d || d.error) continue;
    const { sub } = renderModule(k, d);
    out.push(`${k.padEnd(16)} ${sub || 'ok'}`);
  }
  return out.join('\n');
}
