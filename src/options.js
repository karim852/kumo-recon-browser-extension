import { QUICK_SET } from './engine/registry.js';

const DEFAULTS = {
  theme: 'void',
  modules: QUICK_SET,
  autofill: true,
  badge: true,
  concurrency: 6,
  delayMs: 60,
};
const NAMES = { void: 'VOID', glass: 'VOID GLASS', web: 'WEB 蜘蛛', carbon: 'CARBON' };
const $ = id => document.getElementById(id);

let theme = 'void';

function applyTheme(v) {
  theme = v;
  document.documentElement.setAttribute('data-v', v);
  $('themeName').textContent = NAMES[v] || v.toUpperCase();
  document.querySelectorAll('.theme-dot').forEach(b =>
    b.setAttribute('aria-pressed', String(b.dataset.theme === v)));
}

function flash(el, msg, bad) {
  el.textContent = msg;
  el.classList.toggle('bad', !!bad);
  el.classList.add('on');
  setTimeout(() => el.classList.remove('on'), 2600);
}

const clamp = (v, lo, hi, dflt) => {
  const n = parseInt(v, 10);
  return Number.isNaN(n) ? dflt : Math.min(hi, Math.max(lo, n));
};

(async function init() {
  const cfg = { ...DEFAULTS, ...(await chrome.storage.local.get(DEFAULTS)) };
  $('concurrency').value = cfg.concurrency;
  $('delayMs').value = cfg.delayMs;
  $('autofill').checked = !!cfg.autofill;
  $('badge').checked = !!cfg.badge;
  applyTheme(cfg.theme);

  document.querySelectorAll('.theme-dot').forEach(b => {
    b.onclick = () => { applyTheme(b.dataset.theme); chrome.storage.local.set({ theme: b.dataset.theme }); };
  });

  $('save').onclick = async () => {
    const concurrency = clamp($('concurrency').value, 1, 20, DEFAULTS.concurrency);
    const delayMs = clamp($('delayMs').value, 0, 5000, DEFAULTS.delayMs);
    $('concurrency').value = concurrency;
    $('delayMs').value = delayMs;
    await chrome.storage.local.set({
      concurrency, delayMs, theme,
      autofill: $('autofill').checked,
      badge: $('badge').checked,
    });
    flash($('saveStatus'), '✓ saved');
  };

  $('reset').onclick = async () => {
    await chrome.storage.local.set(DEFAULTS);
    $('concurrency').value = DEFAULTS.concurrency;
    $('delayMs').value = DEFAULTS.delayMs;
    $('autofill').checked = DEFAULTS.autofill;
    $('badge').checked = DEFAULTS.badge;
    applyTheme(DEFAULTS.theme);
    flash($('saveStatus'), '✓ defaults restored');
  };
})();
