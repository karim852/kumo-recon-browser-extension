/* ════════════════════════════════════════════════════════════
   KUMO popup controller.
   The popup owns none of the scan — it subscribes to the worker,
   replays whatever is already there, and paints.
   ════════════════════════════════════════════════════════════ */

import { MODULES, MODULE_KEYS, QUICK_SET, ICONS, DESCS, shortName } from './engine/registry.js';
import { FAST_SKIP } from './engine/runner.js';
import { tallyAll, tallyModule, cardSeverity } from './sev.js';
import { renderModule, digest, esc } from './render.js';

const $ = id => document.getElementById(id);
const DEFAULTS = { theme: 'void', modules: QUICK_SET, autofill: true, badge: true, concurrency: 6, delayMs: 60 };

let cfg = { ...DEFAULTS };
let selected = new Set(QUICK_SET);
let state = null;
let tick = null;
const expanded = new Set();     // module keys whose full finding list is open

/* ── boot ─────────────────────────────────────────────────── */
(async function init() {
  cfg = { ...DEFAULTS, ...(await chrome.storage.local.get(DEFAULTS)) };
  applyTheme(cfg.theme);
  selected = new Set((cfg.modules || QUICK_SET).filter(k => MODULE_KEYS.includes(k)));
  buildPicker();
  wire();

  const { state: s } = await send({ cmd: 'getState' });
  state = s;
  if (state && state.domain) paintAll();
  else await autofillDomain();

  refreshLamp();
})();

function send(msg) {
  return new Promise(res => chrome.runtime.sendMessage(msg, r => {
    if (chrome.runtime.lastError) res({});
    else res(r || {});
  }));
}

/* ── theme ────────────────────────────────────────────────── */
function applyTheme(v) {
  document.documentElement.setAttribute('data-v', v);
  document.querySelectorAll('.theme-dot').forEach(b =>
    b.setAttribute('aria-pressed', String(b.dataset.theme === v)));
}

/* ── active tab → domain ──────────────────────────────────── */
function cleanDomain(raw) {
  let d = String(raw || '').trim().toLowerCase();
  if (!d) return '';
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split('/')[0].split('?')[0].split('#')[0];
  d = d.replace(/^[^@]*@/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (!/^[a-z0-9.-]+$/.test(d) || !d.includes('.') || d === 'localhost') return '';
  return d;
}

async function activeDomain() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab ? cleanDomain(tab.url) : '';
  } catch { return ''; }
}

async function autofillDomain() {
  if (!cfg.autofill) return;
  const d = await activeDomain();
  if (d && !$('dom').value) $('dom').value = d;
}

/* ── module picker ────────────────────────────────────────── */
function buildPicker() {
  const p = $('picker');
  p.innerHTML = MODULES.map(({ key: k }) =>
    `<button class="pill${selected.has(k) ? ' on' : ''}" data-k="${k}" title="${esc(DESCS[k])}${FAST_SKIP.has(k) ? ' — skipped in ⚡ fast mode' : ''}">${esc(shortName(k))}</button>`
  ).join('');
  p.addEventListener('click', e => {
    const b = e.target.closest('.pill'); if (!b) return;
    const k = b.dataset.k;
    if (selected.has(k)) selected.delete(k); else selected.add(k);
    b.classList.toggle('on', selected.has(k));
    saveSelection();
  });
  $('totCount').textContent = MODULES.length;
  refreshCount();
}
function refreshCount() { $('selCount').textContent = selected.size; }
function saveSelection() {
  refreshCount();
  chrome.storage.local.set({ modules: [...selected] });
}
function setSelection(keys) {
  selected = new Set(keys);
  document.querySelectorAll('.pill').forEach(b => b.classList.toggle('on', selected.has(b.dataset.k)));
  saveSelection();
}

/* ── status lamp ──────────────────────────────────────────── */
async function refreshLamp() {
  const lamp = $('lamp');
  lamp.className = 'lamp on';
  $('lampTxt').textContent = 'ready';
  const hint = $('welcomeHint');
  if (hint) hint.innerHTML = 'Everything runs in your browser. No server, no API key, no setup.';
}

/* ── scanning ─────────────────────────────────────────────── */
async function doScan(fast) {
  const domain = cleanDomain($('dom').value) || await activeDomain();
  if (!domain) { toast('Enter a domain first — e.g. example.com', 'err'); return; }
  $('dom').value = domain;
  if (!selected.size) { toast('No modules selected.', 'err'); return; }

  expanded.clear();
  const r = await send({ cmd: 'scan', domain, fast, modules: [...selected] });
  if (!r.ok) { toast(r.error || 'Could not start the scan.', 'err'); return; }
  state = r.state;
  paintAll();
}

/* ── events from the worker ───────────────────────────────── */
chrome.runtime.onMessage.addListener(msg => {
  if (!msg || !msg.evt) return;
  if (msg.evt === 'begin') { state = msg.state; paintAll(); }
  else if (msg.evt === 'module-done') {
    if (!state) return;
    state.results[msg.key] = msg.data;
    state.pending = state.pending.filter(k => k !== msg.key);
    upsertCard(msg.key, msg.data);
    paintSummary(); paintProgress();
  } else if (msg.evt === 'end') { state = msg.state; paintAll(); }
});

/* ── painting ─────────────────────────────────────────────── */
function paintAll() {
  if (!state) return;
  if (state.domain) $('dom').value = state.domain;
  paintButtons(); paintProgress(); paintSummary(); paintStream(); paintTimer();
}

function paintButtons() {
  const running = state && state.status === 'running';
  $('scanBtn').classList.toggle('hide', running);
  $('fastBtn').classList.toggle('hide', running);
  $('stopBtn').classList.toggle('hide', !running);
}

function paintProgress() {
  const p = $('prog');
  if (!state || state.status !== 'running') { p.classList.remove('on'); return; }
  p.classList.add('on');
  const total = state.modules.length || 1;
  const done = total - state.pending.length;
  $('progBar').style.width = `${Math.round((done / total) * 100)}%`;
}

function paintSummary() {
  const el = $('summary');
  if (!state || !Object.keys(state.results || {}).length) { el.classList.remove('on'); return; }
  const t = tallyAll(state.results);
  const total = state.modules.length;
  const done = total - state.pending.length;
  const errs = Object.values(state.results).filter(d => d && d.error).length;

  const chips = [
    `<span class="sum neutral"><b>${done}</b>/${total} modules</span>`,
    t.critical ? `<span class="sum crit"><b>${t.critical}</b> critical</span>` : '',
    t.high ? `<span class="sum high"><b>${t.high}</b> high</span>` : '',
    t.medium ? `<span class="sum med"><b>${t.medium}</b> medium</span>` : '',
    (!t.critical && !t.high && !t.medium && state.status !== 'running')
      ? `<span class="sum ok"><b>✓</b> nothing major</span>` : '',
    errs ? `<span class="sum"><b style="color:var(--text3)">${errs}</b> errored</span>` : '',
  ].filter(Boolean);
  el.innerHTML = chips.join('');
  el.classList.add('on');
}

function paintTimer() {
  clearInterval(tick);
  const t = $('timer');
  if (!state || !state.startedAt) { t.textContent = ''; return; }
  if (state.status === 'running') {
    const run = () => { t.innerHTML = `<b>${((Date.now() - state.startedAt) / 1000).toFixed(1)}s</b>`; };
    run(); tick = setInterval(run, 100);
  } else {
    t.innerHTML = state.duration ? `${state.status} in <b>${esc(state.duration)}</b>` : esc(state.status);
  }
}

function paintStream() {
  const s = $('stream');
  if (!state || !state.domain) return;
  s.innerHTML = '';

  if (state.error) {
    s.insertAdjacentHTML('beforeend',
      `<div class="card sev-crit glow"><div class="card-b"><div class="err">⚠ ${esc(state.error)}</div></div></div>`);
  }

  // Modules in registry order: finished first, then the ones still running.
  for (const k of state.modules) {
    if (k in (state.results || {})) upsertCard(k, state.results[k]);
    else if (state.status === 'running') upsertCard(k, null);
  }
  if (!state.modules.length) s.innerHTML = '';
}

function cardId(k) { return `card-${k}`; }

function upsertCard(key, data) {
  const s = $('stream');
  let card = document.getElementById(cardId(key));
  const running = data == null;

  const sev = running ? '' : cardSeverity(key, data);
  const t = running ? null : tallyModule(key, data);
  const glow = !running && (sev === 'sev-crit' || sev === 'sev-warn');

  const r = running ? null : renderModule(key, data);
  const body = running
    ? `<div class="sk" style="width:72%"></div><div class="sk" style="width:94%"></div><div class="sk" style="width:55%"></div>`
    : r.html;
  const sub = running ? 'running' : (r.sub || '');

  const html = `
    <div class="card-h" data-toggle="${key}">
      <span class="card-ico">${ICONS[key] || '▪'}</span>
      <span class="card-t">${esc(shortName(key))}</span>
      <span class="card-sub">${esc(sub)}</span>
      <span class="card-caret">▾</span>
    </div>
    <div class="card-b">${body}</div>`;

  if (!card) {
    card = document.createElement('section');
    card.id = cardId(key);
    card.className = 'card';
    s.appendChild(card);
  }
  card.className = `card ${running ? 'running' : ''} ${sev} ${glow ? 'glow' : ''}`.replace(/\s+/g, ' ').trim();
  card.innerHTML = html;

  // critical/high cards open, quiet ones collapse — keeps the panel scannable
  if (!running) {
    const loud = t && (t.critical || t.high || t.medium);
    if (!loud && !expanded.has(key)) card.classList.add('collapsed');
  }
  if (expanded.has(key)) card.classList.remove('collapsed');
}

/* ── interactions inside the stream ───────────────────────── */
$('stream').addEventListener('click', e => {
  const head = e.target.closest('[data-toggle]');
  if (head) {
    const k = head.dataset.toggle;
    const card = document.getElementById(cardId(k));
    card.classList.toggle('collapsed');
    if (card.classList.contains('collapsed')) expanded.delete(k); else expanded.add(k);
    return;
  }
  const more = e.target.closest('[data-expand]');
  if (more) {           // re-render that card with every finding shown
    const card = more.closest('.card');
    const k = card.id.replace('card-', '');
    card.querySelector('.card-b').innerHTML = renderModule(k, state.results[k], true).html;
    return;
  }
  const dork = e.target.closest('[data-dork]');
  if (dork) {
    chrome.tabs.create({ url: `https://www.google.com/search?q=${encodeURIComponent(dork.dataset.dork)}` });
  }
});

/* ── wiring ───────────────────────────────────────────────── */
function wire() {
  $('scanBtn').onclick = () => doScan(false);
  $('fastBtn').onclick = () => doScan(true);
  $('stopBtn').onclick = async () => { await send({ cmd: 'stop' }); };
  $('useTab').onclick = async () => {
    const d = await activeDomain();
    if (d) { $('dom').value = d; toast(`Target set to ${d}`, 'ok'); }
    else toast('That tab has no scannable domain.', 'err');
  };
  $('dom').addEventListener('keydown', e => {
    if (e.key === 'Enter') doScan(e.shiftKey);
  });

  $('togglePicker').onclick = () => {
    const open = $('picker').classList.toggle('open');
    $('togglePicker').classList.toggle('active', open);
  };
  $('presetQuick').onclick = () => setSelection(QUICK_SET);
  $('presetAll').onclick = () => setSelection(MODULE_KEYS);
  $('presetNone').onclick = () => setSelection([]);

  document.querySelectorAll('.theme-dot').forEach(b => {
    b.onclick = () => { applyTheme(b.dataset.theme); chrome.storage.local.set({ theme: b.dataset.theme }); };
  });

  $('lamp').onclick = refreshLamp;

  $('exportBtn').onclick = () => {
    if (!state || !Object.keys(state.results || {}).length) { toast('Nothing to export yet.', 'err'); return; }
    const payload = {
      _tool: 'Kumo 蜘蛛 browser extension',
      _domain: state.domain,
      _scanned_at: new Date(state.startedAt).toISOString(),
      _duration: state.duration,
      _mode: state.fast ? 'fast' : 'full',
      ...state.results,
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `kumo-${state.domain}-${new Date(state.startedAt).toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    toast('Scan exported.', 'ok');
  };

  $('copyBtn').onclick = async () => {
    if (!state || !Object.keys(state.results || {}).length) { toast('Nothing to copy yet.', 'err'); return; }
    await navigator.clipboard.writeText(digest(state.domain, state.results));
    toast('Summary copied.', 'ok');
  };

  $('clearBtn').onclick = async () => {
    await send({ cmd: 'clear' });
    state = null; expanded.clear();
    $('stream').innerHTML = `<section class="welcome"><div class="big">🕸</div><h2>KUMO 蜘蛛</h2>
      <p>Cleared. Pick a target and scan again.</p></section>`;
    $('summary').classList.remove('on');
    $('prog').classList.remove('on');
    clearInterval(tick); $('timer').textContent = '';
    paintButtons();
  };

  $('openDash').onclick = () => chrome.tabs.create({ url: 'https://github.com/karim852/KUMO-Domain-Recon-Tool' });
  $('openOpts').onclick = () => chrome.runtime.openOptionsPage();
}

/* ── toasts ───────────────────────────────────────────────── */
function toast(msg, kind) {
  const el = document.createElement('div');
  el.className = `toast ${kind || ''}`;
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 250); }, 2400);
}
