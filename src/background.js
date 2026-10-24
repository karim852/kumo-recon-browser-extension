/* ════════════════════════════════════════════════════════════
   KUMO background worker — standalone.

   The scan runs here, in the worker, using fetch and DNS-over-
   HTTPS. There is no server. The worker owns the run so that
   closing the popup does not kill it, keeps the result set, and
   replays everything when the popup reopens.
   ════════════════════════════════════════════════════════════ */

import { MODULE_KEYS, QUICK_SET } from './engine/registry.js';
import { runScan, FAST_SKIP } from './engine/runner.js';
import { tallyAll } from './sev.js';

const DEFAULTS = {
  theme: 'void',
  modules: QUICK_SET,
  autofill: true,
  badge: true,
  concurrency: 6,
  delayMs: 60,
};

let S = blankState();
let handle = null;
let keepAliveOn = false;

function blankState() {
  return {
    status: 'idle', domain: '', fast: false,
    modules: [], pending: [], results: {},
    startedAt: 0, duration: '', error: '',
  };
}

async function settings() {
  const s = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...s };
}

/* ── persistence, so a worker restart doesn't lose results ─── */
let saveTimer = null;
function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => chrome.storage.session.set({ scanState: S }).catch(() => {}), 120);
}
async function restore() {
  try {
    const { scanState } = await chrome.storage.session.get('scanState');
    if (scanState) {
      S = scanState;
      if (S.status === 'running') { S.status = 'stopped'; S.error = 'Worker restarted — scan interrupted.'; }
    }
  } catch (_) {}
}

const emit = msg => { chrome.runtime.sendMessage(msg).catch(() => {}); };

/* ── badge ──────────────────────────────────────────────────── */
async function paintBadge() {
  const { badge } = await settings();
  if (!badge) return chrome.action.setBadgeText({ text: '' });

  if (S.status === 'running') {
    chrome.action.setBadgeBackgroundColor({ color: '#5cb0ff' });
    return chrome.action.setBadgeText({ text: String(S.modules.length - S.pending.length) });
  }
  if (S.status === 'idle') return chrome.action.setBadgeText({ text: '' });

  const t = tallyAll(S.results);
  const [color, text] =
    t.critical ? ['#ff5f57', String(Math.min(t.critical, 99))] :
    t.high ? ['#ffa657', String(Math.min(t.high, 99))] :
    t.medium ? ['#e3b341', String(Math.min(t.medium, 99))] :
    ['#2aab68', '✓'];
  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setBadgeText({ text });
}

/* Chrome evicts an idle service worker after ~30s. A full scan now runs for
   minutes (nuclei alone has a 10-minute budget), so the worker has to be held
   open deliberately. Two belts:
     · an alarm at the documented 30s minimum — anything lower is clamped, and
       a clamped alarm racing a 30s idle timer is how scans quietly die;
     · a 20s interval calling a chrome API, which resets the idle timer from
       inside, covering the gap between an alarm and the next request.
   Network activity during a scan helps too, but a slow module can go quiet
   for long enough to lose the worker without these. */
let keepTimer = null;
function keepAlive(on) {
  keepAliveOn = on;
  if (on) {
    chrome.alarms.create('kumo-keepalive', { periodInMinutes: 0.5 });
    clearInterval(keepTimer);
    keepTimer = setInterval(() => {
      if (!keepAliveOn) return clearInterval(keepTimer);
      chrome.runtime.getPlatformInfo().catch(() => {});
    }, 20000);
  } else {
    chrome.alarms.clear('kumo-keepalive');
    clearInterval(keepTimer);
    keepTimer = null;
  }
}
chrome.alarms.onAlarm.addListener(a => {
  if (a.name === 'kumo-keepalive' && keepAliveOn) chrome.storage.session.get('scanState');
});

/* ── domain extraction ──────────────────────────────────────── */
export function cleanDomain(raw) {
  let d = String(raw || '').trim().toLowerCase();
  if (!d) return '';
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split('/')[0].split('?')[0].split('#')[0];
  d = d.replace(/^[^@]*@/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (!/^[a-z0-9.-]+$/.test(d) || !d.includes('.') || d === 'localhost') return '';
  // Nothing in the engine can act on a bare IP meaningfully, and probing one
  // by accident from a tab is worse than refusing.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(d)) return '';
  return d;
}

/* ── the scan ───────────────────────────────────────────────── */
async function startScan({ domain, fast = false, modules }) {
  const d = cleanDomain(domain);
  if (!d) return { ok: false, error: 'That does not look like a scannable domain.' };
  if (S.status === 'running') return { ok: false, error: 'A scan is already running.' };

  const cfg = await settings();
  let keys = (modules && modules.length ? modules : cfg.modules).filter(k => MODULE_KEYS.includes(k));
  if (!keys.length) keys = QUICK_SET.slice();
  const effective = fast ? keys.filter(k => !FAST_SKIP.has(k)) : keys;
  if (!effective.length) return { ok: false, error: 'Fast mode skipped every selected module.' };

  S = blankState();
  Object.assign(S, {
    status: 'running', domain: d, fast,
    modules: effective.slice(), pending: effective.slice(),
    startedAt: Date.now(),
  });
  persist(); paintBadge();
  emit({ evt: 'begin', state: S });
  keepAlive(true);

  handle = runScan(
    { domain: d, modules: effective, fast, concurrency: cfg.concurrency, delayMs: cfg.delayMs },
    handleEvent,
  );
  return { ok: true, state: S };
}

function handleEvent(ev) {
  switch (ev.type) {
    case 'start':
      emit({ evt: 'module-start', key: ev.module, description: ev.description });
      break;
    case 'done':
      S.results[ev.module] = ev.data;
      S.pending = S.pending.filter(k => k !== ev.module);
      persist(); paintBadge();
      emit({ evt: 'module-done', key: ev.module, description: ev.description, data: ev.data,
             pending: S.pending.length, total: S.modules.length });
      break;
    case 'complete':
      S.duration = ev.duration;
      finish('done', ev.timed_out ? `${ev.timed_out_count} module(s) timed out.` : '');
      break;
    case 'stopped':
      S.duration = ev.duration;
      finish('stopped', '');
      break;
  }
}

function finish(status, error) {
  S.status = status;
  S.error = error || '';
  S.pending = [];
  if (!S.duration && S.startedAt) S.duration = `${((Date.now() - S.startedAt) / 1000).toFixed(1)}s`;
  keepAlive(false);
  handle = null;
  persist(); paintBadge();
  emit({ evt: 'end', state: S });
}

function stopScan() {
  if (S.status !== 'running' || !handle) return { ok: false };
  handle.stop();
  return { ok: true };
}

/* ── messages ───────────────────────────────────────────────── */
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  (async () => {
    switch (msg && msg.cmd) {
      case 'getState': reply({ state: S }); break;
      case 'scan': reply(await startScan(msg)); break;
      case 'stop': reply(stopScan()); break;
      case 'clear': S = blankState(); persist(); paintBadge(); reply({ ok: true }); break;
      default: reply({ ok: false, error: 'unknown command' });
    }
  })();
  return true;
});

/* ── context menus ──────────────────────────────────────────── */
function installMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'kumo-scan-page', title: 'Kumo: scan this site', contexts: ['page', 'frame'] });
    chrome.contextMenus.create({ id: 'kumo-scan-link', title: "Kumo: scan this link's domain", contexts: ['link'] });
  });
}
chrome.runtime.onInstalled.addListener(() => { installMenus(); restore(); });
chrome.runtime.onStartup.addListener(() => { installMenus(); restore(); });

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const d = cleanDomain(info.menuItemId === 'kumo-scan-link' ? info.linkUrl : (info.pageUrl || (tab && tab.url)));
  if (!d) return;
  await startScan({ domain: d, fast: true });
  try { await chrome.action.openPopup(); } catch (_) {}
});

restore();
