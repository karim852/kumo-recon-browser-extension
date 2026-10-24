/* ════════════════════════════════════════════════════════════
   Severity model — one place, used by the badge, the summary
   chips and the per-card glow, so they can never disagree.
   ════════════════════════════════════════════════════════════ */

const ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const norm = s => {
  s = String(s || '').toLowerCase();
  if (s === 'crit') return 'critical';
  return ORDER.includes(s) ? s : 'info';
};

export const blankTally = () => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });

/* Engine fields flip between "a count" and "the list itself" depending on the
   module and version — read either as a number. */
export const count = v => Array.isArray(v) ? v.length : (Number(v) || 0);

/* CVSS v3 bands, used when a module hands us scores instead of labels. */
export const cvssSeverity = n => {
  n = Number(n);
  if (Number.isNaN(n)) return 'info';
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  return 'low';
};

/* Pull a severity tally out of one module's result payload. */
export function tallyModule(key, d) {
  const t = blankTally();
  if (!d || typeof d !== 'object' || d.error) return t;

  const bump = (sev, n = 1) => { t[norm(sev)] += n; };
  const fromList = list => (list || []).forEach(f => bump(f && f.severity));

  // Modules that already carry a severity_counts block.
  if (d.severity_counts && typeof d.severity_counts === 'object') {
    for (const [k, v] of Object.entries(d.severity_counts)) bump(k, Number(v) || 0);
    return t;
  }

  switch (key) {
    case 'headers': {
      const g = String(d.grade || '')[0];
      if (g === 'F' || g === 'E') bump('high');
      else if (g === 'D' || g === 'C') bump('medium');
      (d.headers || []).forEach(h => { if (!h.present) bump(h.severity || 'low'); });
      (d.disclosure || []).forEach(() => bump('low'));
      break;
    }
    case 'dns': {
      const es = d.email_security || {};
      ['spf', 'dmarc', 'dkim'].forEach(k => {
        const v = es[k];
        const ok = v === true || (v && (v.found || v.present || v.valid));
        if (!ok) bump(k === 'dkim' ? 'low' : 'medium');
      });
      break;
    }
    case 'ssl': {
      const dl = Number(d.days_left);
      if (!Number.isNaN(dl)) { if (dl < 0) bump('critical'); else if (dl < 15) bump('high'); else if (dl < 30) bump('medium'); }
      if (/TLSv1(\.[01])?$/.test(String(d.protocol || ''))) bump('high');
      break;
    }
    case 'whois': {
      if (d.rdap_available === false) break;   // nothing known, nothing to grade
      const dd = Number(d.days_until_expiry);
      if (!Number.isNaN(dd)) { if (dd < 0) bump('critical'); else if (dd < 30) bump('high'); }
      break;
    }
    case 'ports':
      (d.open || []).forEach(p => {
        const r = String(p.risk || '').toLowerCase();
        if (r.includes('crit')) bump('critical');
        else if (r.includes('high')) bump('high');
        else if (r.includes('med')) bump('medium');
      });
      break;
    case 'js_secrets':       fromList(d.secrets); break;
    case 'cloud_buckets':    fromList(d.exposed); break;
    case 'api_fuzzer':
      fromList(d.specs); fromList(d.findings);
      if (d.graphql && d.graphql.severity) bump(d.graphql.severity);
      break;
    case 'breachintel': {
      const s = d.summary || {};
      if (Number(s.total_infostealer_hits) > 0) bump('critical');
      if (Number(s.total_employees_leaked) > 0) bump('high');
      if (Number(s.total_clients_leaked) > 0) bump('high');
      break;
    }
    case 'shodan': {
      // critical_cves is a LIST of {cve,cvss,ip} in some engine versions and a
      // plain count in others — accept both, and fall back to grading by CVSS.
      const s = d.summary || {};
      const crit = count(s.critical_cves);
      const total = count(s.total_cves);
      if (crit || total) {
        bump('critical', crit);
        bump('medium', Math.max(0, total - crit));
      } else {
        for (const ip of Object.values(d.ips || {})) {
          for (const c of (ip.cves || ip.vulns || [])) bump(cvssSeverity(c && c.cvss));
        }
      }
      break;
    }
    case 'subdomains':
    case 'brute':
      (d.sensitive || []).forEach(() => bump('medium'));
      (d.ct_sensitive || []).forEach(() => bump('low'));
      break;
    case 'http_inspect':
      ((d.methods || {}).dangerous || []).forEach(() => bump('medium'));
      (d.cookies || []).forEach(c => { if (c.secure === false || c.httponly === false) bump('low'); });
      break;
    case 'screenshot':
      if (d.ransomware_status && d.ransomware_status !== 'clean'
          && !/not checked|unknown/i.test(d.ransomware_status)) bump('critical');
      if (Number((d.threat_feeds || {}).hits) > 0) bump('high');
      break;
    case 'wayback':
      (d.interesting || []).forEach(() => bump('low'));
      break;
    case 'content_intel': {
      const c = d.categories || {};
      (c.internal_hosts || []).forEach(() => bump('low'));
      (c.databases || []).forEach(() => bump('medium'));
      break;
    }
    default:
      fromList(d.findings);
  }
  return t;
}

export function tallyAll(results) {
  const t = blankTally();
  for (const [k, d] of Object.entries(results || {})) {
    const m = tallyModule(k, d);
    for (const s of ORDER) t[s] += m[s];
  }
  return t;
}

/* Card glow class from a module's own tally. */
export function cardSeverity(key, d) {
  if (!d || d.error) return '';
  const t = tallyModule(key, d);
  if (t.critical || t.high) return 'sev-crit';
  if (t.medium) return 'sev-warn';
  if (t.low || t.info) return '';
  return 'sev-ok';
}

export const SEV_COLOR = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)',
  low: 'var(--cyan)', info: 'var(--text2)',
};
export const sevKey = norm;
