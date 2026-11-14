import { parseOtp, otpLabel, totpCode, secondsLeft, groupCode } from './src/totp.js';
import { urlMatches, hostOf } from './src/match.js';
import { silkFill } from './src/fill.js';
import { VaultError } from './src/vault.js';
import { isLogin, kindName, blank, subtitle, sameLogin, NEW_KINDS } from './src/entry.js';
import { generate, entropyBits, normalize, MIN_LEN, MAX_LEN } from './src/generator.js';
import { importFile, exportCsv, exportJson, ImportError } from './src/transfer.js';
import { CLOUD, cloudSession, signInAndDownload, signOut, syncNow } from './src/cloud.js';
import { exclusive, loadVault, storeVault, startSession, ensureUnlocked, touchSession, lockAll, setKeep, saveEntries, reopenSession, loadPrefs, savePrefs } from './src/state.js';

const MAX_FILE = 8 * 1024 * 1024; // chrome.storage.local allows 10 MB

const app = document.getElementById('app');
const st = { vault: null, header: null, name: '', entries: null, tab: 'logins', query: '', page: null, msg: '', err: '', busy: false, keyFile: null, keyName: '', timer: null, view: '', email: '', cloud: null, prefs: null, edit: null, gen: '' };

// ------------------------------------------------------------------ small helpers

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const $ = (sel) => app.querySelector(sel);
const readFile = async (file) => new Uint8Array(await file.arrayBuffer());
const byTitle = (a, b) => a.title.toLowerCase().localeCompare(b.title.toLowerCase());
const now = () => Math.floor(Date.now() / 1000);

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

async function loadState() {
  const vault = await loadVault();
  if (vault) {
    st.vault = vault.bytes;
    st.header = vault.header;
    st.name = vault.name;
  }
  [st.prefs, st.cloud] = await Promise.all([loadPrefs(), cloudSession()]);
  if (st.cloud) st.email = st.cloud.email || '';
  // "Opens instantly": with the kept key this opens the vault without a password, even after a browser restart.
  const open = vault ? await exclusive(ensureUnlocked) : null;
  if (open) {
    st.entries = open.entries;
    await touchSession();
  }
  const tab = await currentTab();
  st.page = tab && tab.url ? { id: tab.id, url: tab.url } : null;
}

async function lock() {
  await exclusive(lockAll);
  st.entries = null;
  st.edit = null;
  st.query = '';
  st.msg = '';
  st.err = '';
  render();
}

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    st.msg = `${what} copied. It stays on the clipboard until you copy something else.`;
    st.err = '';
  } catch {
    st.err = 'The browser refused to copy.';
  }
  await touchSession();
  renderMessages();
}

function download(name, data, type) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// ------------------------------------------------------------------ views

function render() {
  clearInterval(st.timer);
  st.timer = null;
  if (!st.vault || st.view === 'login') return renderLogin();
  if (!st.entries) return renderUnlock();
  if (st.edit) return renderEdit();
  renderMain();
}

function messages() {
  return `${st.err ? `<p class="error" role="alert">${esc(st.err)}</p>` : ''}${st.msg ? `<p class="notice">${esc(st.msg)}</p>` : ''}`;
}

function renderMessages() {
  const box = $('#messages');
  if (box) box.innerHTML = messages();
}

function renderLogin() {
  const busy = st.busy ? 'disabled' : '';
  const signIn = `
    <p>Sign in with your Silk account once. Silk keeps you signed in on this browser, so it opens straight to your vault from then on and stays in step with your phone.</p>
    <input id="email" type="email" placeholder="Account email" autocomplete="username" spellcheck="false" value="${esc(st.email)}" ${busy}>
    <input id="acct" type="password" placeholder="Account password" autocomplete="current-password" ${busy}>
    <button class="primary" id="signin" ${busy}>${st.busy ? 'Signing in…' : 'Sign in'}</button>`;
  app.innerHTML = `
    <div class="brand"><img src="icons/48.png" alt=""><h1>Silk</h1></div>
    ${CLOUD ? signIn : '<p>Cloud sign-in isn’t set up in this build. Add your vault from a backup file instead.</p>'}
    <div id="messages">${messages()}</div>
    ${CLOUD ? '<div class="or">or</div>' : ''}
    <input id="file" type="file" hidden>
    <button id="pick" ${CLOUD ? '' : 'class="primary"'}>Choose a backup file</button>
    <p class="muted">In the Android app open <b>More</b> and tap <b>Back up vault</b>, move the <code>.silk</code> file to this computer, then choose it here.</p>
    ${st.vault ? '<div class="row"><button class="link small" id="back">Back</button></div>' : ''}`;
  $('#pick').onclick = () => $('#file').click();
  $('#file').onchange = async (e) => {
    const f = e.target.files[0];
    if (f) await importVault(f);
  };
  if (st.vault) {
    $('#back').onclick = () => {
      st.view = '';
      st.err = '';
      st.msg = '';
      render();
    };
  }
  if (!CLOUD) return;
  const email = $('#email');
  const acct = $('#acct');
  email.oninput = () => { st.email = email.value; };
  email.onkeydown = acct.onkeydown = (e) => { if (e.key === 'Enter') signInCloud(); };
  $('#signin').onclick = signInCloud;
  (st.email ? acct : email).focus();
}

// ------------------------------------------------------------------ cloud sign-in
// The steps live in src/cloud.js. After the first sign-in only a refresh token is kept (sealed by a key
// this browser cannot export), so later opens and syncs need no password.

async function signInCloud() {
  if (st.busy) return;
  const email = $('#email').value.trim();
  const password = $('#acct').value;
  st.email = email;
  st.err = '';
  st.msg = '';
  if (!email || !password) {
    st.err = 'Enter the account email and password.';
    return renderMessages();
  }
  st.busy = true;
  const btn = $('#signin');
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  try {
    const { bytes, uid } = await signInAndDownload(email, password);
    const header = await exclusive(() => storeVault(bytes, `Cloud vault · ${email}`, { deliberate: true, uid }));
    st.header = header;
    st.vault = bytes;
    st.name = `Cloud vault · ${email}`;
    st.cloud = await cloudSession();
    st.entries = null;
    st.view = '';
    st.msg = 'Signed in. Enter your master password once; after that Silk opens without asking.';
  } catch (e) {
    st.err = e instanceof VaultError ? e.message : 'Couldn’t download the vault.';
    btn.disabled = false;
    btn.textContent = 'Sign in';
    st.busy = false;
    return renderMessages();
  }
  st.busy = false;
  render();
}

async function importVault(file) {
  st.err = '';
  st.msg = '';
  if (file.size > MAX_FILE) {
    st.err = 'That file is too large to be a Silk backup.';
    return render();
  }
  try {
    const bytes = await readFile(file);
    st.header = await exclusive(() => storeVault(bytes, file.name, { deliberate: true, uid: '' }));
    st.vault = bytes;
    st.name = file.name;
    st.entries = null;
    st.msg = 'Vault added. Enter its password to unlock it.';
    st.view = '';
  } catch (e) {
    st.err = e instanceof VaultError ? e.message : 'Couldn’t read that file.';
  }
  render();
}

// ------------------------------------------------------------------ unlock

function renderUnlock() {
  const needsKey = st.header.keyFile;
  app.innerHTML = `
    <div class="brand"><img src="icons/48.png" alt=""><h1>Unlock vault</h1></div>
    <p class="muted">${esc(st.name)}</p>
    <input id="pw" type="password" placeholder="Master password" autocomplete="off" ${st.busy ? 'disabled' : ''}>
    ${needsKey ? `<div class="row"><span class="grow muted">${st.keyName ? esc(st.keyName) : 'This vault needs its key file'}</span>
      <input id="kf" type="file" hidden><button class="small" id="pickkey">Choose key file</button></div>` : ''}
    <label class="check"><input type="checkbox" id="keep" ${st.prefs.keep ? 'checked' : ''}> <span>Stay unlocked until I press Lock<br><span class="muted">Silk then opens instantly, even after you restart the browser.</span></span></label>
    <button class="primary" id="go" ${st.busy ? 'disabled' : ''}>${st.busy ? 'Unlocking…' : 'Unlock'}</button>
    <div id="messages">${messages()}</div>
    <div class="row">${CLOUD && !st.cloud ? '<button class="link small" id="cloud">Sign in</button>' : ''}<button class="link small" id="other">Use a different vault file</button></div>
    <input id="file" type="file" hidden>`;
  $('#pw').focus();
  $('#pw').onkeydown = (e) => { if (e.key === 'Enter') unlock(); };
  $('#go').onclick = unlock;
  $('#other').onclick = () => $('#file').click();
  const cloud = $('#cloud');
  if (cloud) {
    cloud.onclick = () => {
      if (st.busy) return;
      st.view = 'login';
      st.err = '';
      st.msg = '';
      render();
    };
  }
  $('#file').onchange = async (e) => { if (e.target.files[0]) await importVault(e.target.files[0]); };
  if (needsKey) {
    $('#pickkey').onclick = () => $('#kf').click();
    $('#kf').onchange = async (e) => {
      const f = e.target.files[0];
      if (!f) return;
      st.keyFile = await readFile(f);
      st.keyName = f.name;
      render();
    };
  }
}

function unlock() {
  const pw = $('#pw').value;
  if (!pw || st.busy) return;
  const keep = $('#keep').checked;
  st.busy = true;
  st.err = '';
  st.msg = '';
  const go = $('#go');
  go.disabled = true;
  const worker = new Worker(new URL('./src/worker.js', import.meta.url), { type: 'module' });
  worker.onmessage = async (ev) => {
    if (ev.data.progress !== undefined) {
      go.textContent = `Unlocking… ${Math.round(ev.data.progress * 100)}%`;
      return;
    }
    worker.terminate();
    st.busy = false;
    if (ev.data.error) {
      st.err = ev.data.error.message;
      return render();
    }
    const { entries, vek, revision } = ev.data;
    try {
      await exclusive(() => startSession(entries, vek, keep, BigInt(revision)));
      await savePrefs({ keep });
      st.prefs.keep = keep;
      st.entries = entries;
      st.keyFile = null;
      st.keyName = '';
    } catch (e) {
      st.err = e instanceof VaultError ? e.message : 'Couldn’t open the vault in this browser.';
    } finally {
      vek.fill(0);
    }
    render();
    if (st.entries) backgroundSync();
  };
  worker.onerror = () => {
    worker.terminate();
    st.busy = false;
    st.err = 'Couldn’t unlock the vault in this browser.';
    render();
  };
  worker.postMessage({ file: st.vault, password: pw, keyFile: st.keyFile });
}

// ------------------------------------------------------------------ sync

const SYNC_MESSAGES = {
  off: 'Cloud sync isn’t set up in this build.',
  'signed-out': 'Sign in to your Silk account to sync.',
  upToDate: 'Already up to date.',
  uploaded: 'Synced: your changes are in the cloud.',
  downloaded: 'Synced: a newer vault from your phone was loaded.',
  cloudNewer: 'The cloud copy is newer than this one. Use Sync now to load it (it replaces changes made only here).',
  conflict: 'This browser and the cloud both changed. Nothing was copied; your next save here wins.',
  unlinked: 'This vault came from a file, so it isn’t linked to your account. Sign in again to replace it with the cloud copy.',
};

/** Syncs and refreshes what's on screen. `quiet` hides "up to date". Returns the report, or null on failure. */
async function runSync(mode, quiet) {
  try {
    const { report } = await syncNow(mode);
    if (report === 'downloaded') {
      const entries = await exclusive(reopenSession);
      st.entries = entries;
      if (!entries) st.view = '';
    }
    st.cloud = await cloudSession();
    if (!(quiet && (report === 'upToDate' || report === 'signed-out' || report === 'off'))) {
      st.msg = SYNC_MESSAGES[report] || '';
      st.err = '';
    }
    return report;
  } catch (e) {
    if (!quiet) st.err = e instanceof VaultError ? e.message : 'Couldn’t sync. Check your connection.';
    if (e && e.code === 'signed-out') st.cloud = await cloudSession();
    return null;
  }
}

async function backgroundSync() {
  if (!st.cloud) return;
  const report = await runSync('sync', true);
  if (report === 'downloaded' && !st.edit) render();
  else if (st.entries && !st.edit && st.tab === 'more') renderMessages();
}

// ------------------------------------------------------------------ main

function renderMain() {
  const tabs = [['logins', 'Items'], ['codes', 'Codes'], ['generator', 'Generator'], ['more', 'More']];
  app.innerHTML = `
    <div class="row"><div class="brand grow"><img src="icons/48.png" alt=""><h1>Silk</h1></div><button class="small" id="add">New</button><button class="link" id="lock">Lock</button></div>
    <div class="tabs" role="tablist">${tabs.map(([id, label]) => `<button role="tab" id="t-${id}" aria-selected="${st.tab === id}">${label}</button>`).join('')}</div>
    <div id="messages">${messages()}</div>
    <div id="body"></div>`;
  $('#lock').onclick = lock;
  $('#add').onclick = () => {
    st.edit = { e: blank('login', st.page && /^https?:/.test(st.page.url) ? { url: new URL(st.page.url).origin } : {}), isNew: true, show: false };
    render();
  };
  for (const [id] of tabs) {
    $(`#t-${id}`).onclick = () => {
      st.tab = id;
      st.msg = '';
      st.err = '';
      render();
    };
  }
  if (st.tab === 'logins') renderLogins();
  else if (st.tab === 'codes') renderCodes();
  else if (st.tab === 'generator') renderGenerator();
  else renderMore();
}

function matches(e, q) {
  if (!q) return true;
  const s = q.toLowerCase();
  return e.title.toLowerCase().includes(s) || e.username.toLowerCase().includes(s) || e.url.toLowerCase().includes(s);
}

function itemHtml(e, here) {
  const login = isLogin(e);
  const sub = [subtitle(e), login && e.url ? hostOf(e.url) : ''].filter(Boolean).join(' · ');
  return `<div class="item" data-id="${esc(e.id)}">
    <div><div class="title">${esc(e.title || '(untitled)')}${login ? '' : ` <span class="badge">${esc(kindName(e))}</span>`}</div><div class="sub">${esc(sub)}</div></div>
    <div class="actions">
      ${login && st.page ? `<button class="small ${here ? 'primary' : ''}" data-act="fill">Fill</button>` : ''}
      ${login && e.username ? '<button class="small" data-act="user">Copy user</button>' : ''}
      ${login && e.password ? '<button class="small" data-act="pass">Copy password</button>' : ''}
      ${login && parseOtp(e.otp) ? '<button class="small" data-act="otp">Copy code</button>' : ''}
      <button class="small" data-act="edit">Edit</button>
    </div></div>`;
}

function renderLogins() {
  const body = $('#body');
  const shown = st.entries.filter((e) => e.kind !== 'folder' && matches(e, st.query)).sort(byTitle);
  const here = st.page ? shown.filter((e) => isLogin(e) && urlMatches(e.url, st.page.url)) : [];
  const rest = shown.filter((e) => !here.includes(e));
  body.innerHTML = `
    <input id="q" type="search" placeholder="Search" value="${esc(st.query)}">
    ${st.prefs.tipDismissed ? '' : '<div class="tip"><span>Click a password field on any site to fill it from Silk, or press <b>Ctrl+Shift+F</b>.</span><button class="link small" id="tip">OK</button></div>'}
    <div class="list">
      ${here.length ? `<div class="section">This site</div>${here.map((e) => itemHtml(e, true)).join('')}` : ''}
      ${rest.length ? `<div class="section">${here.length ? 'All items' : 'Items'}</div>${rest.map((e) => itemHtml(e, false)).join('')}` : ''}
      ${shown.length ? '' : `<p>${st.query ? 'Nothing matches your search.' : 'This vault is empty. Choose New to add something.'}</p>`}
    </div>`;
  const q = $('#q');
  q.oninput = () => { st.query = q.value; const pos = q.selectionStart; renderLogins(); const n = $('#q'); n.focus(); n.setSelectionRange(pos, pos); touchSession(); };
  const tip = $('#tip');
  if (tip) {
    tip.onclick = async () => {
      st.prefs.tipDismissed = true;
      await savePrefs({ tipDismissed: true });
      renderLogins();
    };
  }
  body.querySelectorAll('.item').forEach((row) => {
    const e = st.entries.find((x) => x.id === row.dataset.id);
    row.querySelectorAll('button').forEach((b) => {
      b.onclick = () => act(b.dataset.act, e);
    });
  });
}

async function act(what, e) {
  st.err = '';
  st.msg = '';
  if (what === 'user') return copy(e.username, 'Username');
  if (what === 'pass') return copy(e.password, 'Password');
  if (what === 'otp') {
    const p = parseOtp(e.otp);
    return p ? copy(await totpCode(p, now()), 'Code') : null;
  }
  if (what === 'edit') {
    st.edit = { e: structuredClone(e), isNew: false, show: false };
    return render();
  }
  if (what === 'fill') return fill(e, null);
  if (what === 'fillcode') return fill(e, await totpCode(parseOtp(e.otp), now()));
  return null;
}

async function fill(e, code) {
  const tab = await currentTab();
  if (!tab || !tab.url || !/^https?:/.test(tab.url)) {
    st.err = 'Open a web page first.';
    return renderMessages();
  }
  if (!urlMatches(e.url, tab.url)) {
    const site = hostOf(tab.url);
    const ok = confirm(`This login is saved for ${e.url ? hostOf(e.url) : 'no website'}, but you are on ${site}.\n\nFill it here anyway? Only do this if you trust ${site}.`);
    if (!ok) return null;
  }
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: silkFill, args: [code ? '' : e.username, code ? '' : e.password, code || ''] });
    const r = res && res.result;
    if (code) {
      if (r && r.code) st.msg = 'Code filled.';
      else {
        st.msg = '';
        st.err = 'No code field found on this page. Copy the code instead.';
      }
    } else if (r && (r.user || r.pass)) {
      await touchSession();
      return window.close();
    } else {
      st.err = 'No login form found on this page.';
    }
  } catch {
    st.err = 'The browser doesn’t allow filling this page.';
  }
  await touchSession();
  return renderMessages();
}

function renderCodes() {
  const body = $('#body');
  const withOtp = st.entries.filter(isLogin).map((e) => ({ e, p: parseOtp(e.otp) })).filter((x) => x.p).sort((a, b) => byTitle(a.e, b.e));
  if (!withOtp.length) {
    body.innerHTML = '<p>No logins in this vault have a one-time password secret yet. Open a login with Edit and paste the secret or its otpauth link.</p>';
    return;
  }
  body.innerHTML = `<div class="list">${withOtp.map(({ e }, i) => `
    <div class="item" data-i="${i}">
      <div><div class="title">${esc(e.title)}</div><div class="sub">${esc(e.username)}</div></div>
      <button class="otp" data-act="copy" title="Copy code"><span class="code">------</span><span class="bar"><i style="width:0"></i></span><span class="muted">Click to copy</span></button>
      ${st.page ? '<div class="actions"><button class="small" data-act="fillcode">Fill code</button></div>' : ''}
    </div>`).join('')}</div>`;
  const cache = new Map();
  const tick = async () => {
    const t = now();
    for (const [i, { p }] of withOtp.entries()) {
      const key = `${i}:${Math.floor(t / p.period)}`;
      let code = cache.get(i);
      if (!code || code.key !== key) {
        code = { key, text: await totpCode(p, t) };
        cache.set(i, code);
      }
      const row = body.querySelector(`.item[data-i="${i}"]`);
      if (!row) return;
      const left = secondsLeft(p, t);
      row.querySelector('.code').textContent = groupCode(code.text);
      row.querySelector('.bar > i').style.width = `${(left / p.period) * 100}%`;
      row.querySelector('.otp').classList.toggle('urgent', left <= 5);
    }
  };
  body.querySelectorAll('.item').forEach((row) => {
    const { e, p } = withOtp[Number(row.dataset.i)];
    row.querySelector('[data-act="copy"]').onclick = async () => copy(await totpCode(p, now()), 'Code');
    const f = row.querySelector('[data-act="fillcode"]');
    if (f) f.onclick = () => act('fillcode', e);
  });
  tick();
  st.timer = setInterval(tick, 500);
}

// ------------------------------------------------------------------ generator

function renderGenerator() {
  const body = $('#body');
  const o = st.prefs.gen;
  if (!st.gen) st.gen = generate(o);
  const opt = (key, label) => `<label class="check"><input type="checkbox" data-opt="${key}" ${o[key] ? 'checked' : ''}> <span>${label}</span></label>`;
  body.innerHTML = `
    <div class="gen"><code id="gen-out">${esc(st.gen)}</code></div>
    <p class="muted" id="gen-bits"></p>
    <div class="row"><button class="primary grow" id="gen-copy">Copy</button><button id="gen-new">New</button></div>
    <label class="field">Length: <b id="gen-len">${o.length}</b>
      <input type="range" id="gen-range" min="${MIN_LEN}" max="${MAX_LEN}" value="${o.length}"></label>
    ${opt('lower', 'Lowercase (a–z)')}${opt('upper', 'Uppercase (A–Z)')}${opt('digits', 'Digits (0–9)')}${opt('symbols', 'Symbols (!@#…)')}${opt('avoidLookalikes', 'Avoid look-alikes (l I 1 O 0 o)')}`;
  const bits = () => { $('#gen-bits').textContent = `About ${Math.round(entropyBits(st.prefs.gen))} bits of strength`; };
  const again = () => { st.gen = generate(st.prefs.gen); $('#gen-out').textContent = st.gen; bits(); };
  const change = async (patch) => {
    st.prefs.gen = normalize({ ...st.prefs.gen, ...patch });
    await savePrefs({ gen: st.prefs.gen });
    renderGenerator();
    again();
  };
  bits();
  $('#gen-new').onclick = again;
  $('#gen-copy').onclick = () => copy(st.gen, 'Password');
  $('#gen-range').oninput = (ev) => { $('#gen-len').textContent = ev.target.value; };
  $('#gen-range').onchange = (ev) => change({ length: Number(ev.target.value) });
  body.querySelectorAll('[data-opt]').forEach((c) => {
    c.onchange = () => change({ [c.dataset.opt]: c.checked });
  });
}

// ------------------------------------------------------------------ more

function renderMore() {
  const body = $('#body');
  const synced = async () => {
    const { lastSync } = await chrome.storage.local.get('lastSync');
    const el = $('#last-sync');
    if (el) el.textContent = lastSync ? `Last synced ${new Date(lastSync).toLocaleString()}` : 'Not synced yet';
  };
  body.innerHTML = `
    <div class="section">Unlocking</div>
    <label class="check"><input type="checkbox" id="keep" ${st.prefs.keep ? 'checked' : ''}> <span>Stay unlocked until I press Lock<br><span class="muted">Off: Silk locks itself after 5 idle minutes.</span></span></label>
    <div class="section">Account</div>
    ${st.cloud
      ? `<p>${esc(st.cloud.email || 'Signed in')}</p><p class="muted" id="last-sync"></p>
         <div class="actions"><button class="small" id="sync">Sync now</button><button class="small" id="signout">Sign out</button></div>`
      : CLOUD ? '<p class="muted">Not signed in. Sign in once to sync with your phone.</p><div class="actions"><button class="small" id="signin-view">Sign in</button></div>' : '<p class="muted">Cloud sync isn’t set up in this build.</p>'}
    <div class="section">Backup</div>
    <div class="actions"><button class="small" id="dl">Download encrypted backup</button><button class="small" id="other">Use a different file</button></div>
    <div class="section">Move logins</div>
    <p class="muted">Proton Pass JSON or CSV exports. Exported files are not encrypted.</p>
    <div class="actions"><button class="small" id="imp">Import</button><button class="small" id="exp-csv">Export CSV</button><button class="small" id="exp-json">Export JSON</button></div>
    <input id="file" type="file" hidden><input id="impfile" type="file" accept=".json,.csv,text/csv,application/json" hidden>`;
  if (st.cloud) synced();
  $('#keep').onchange = async (ev) => {
    const keep = ev.target.checked;
    st.prefs.keep = keep;
    await savePrefs({ keep });
    await exclusive(() => setKeep(keep));
  };
  const sync = $('#sync');
  if (sync) {
    sync.onclick = async () => {
      sync.disabled = true;
      sync.textContent = 'Syncing…';
      await runSync('sync', false);
      render();
    };
    $('#signout').onclick = async () => {
      await signOut();
      st.cloud = null;
      st.msg = 'Signed out. The vault stays in this browser.';
      render();
    };
  }
  const si = $('#signin-view');
  if (si) {
    si.onclick = () => {
      st.view = 'login';
      render();
    };
  }
  $('#dl').onclick = () => {
    download(`silk-backup-${new Date().toISOString().slice(0, 10)}.silk`, st.vault, 'application/octet-stream');
    st.msg = 'Backup downloaded. It is encrypted: it needs your master password.';
    renderMessages();
  };
  $('#other').onclick = () => $('#file').click();
  $('#file').onchange = async (e) => {
    const f = e.target.files[0];
    if (f && confirm('Replace the vault in this browser with this file?')) {
      st.view = '';
      await importVault(f);
    }
  };
  $('#imp').onclick = () => $('#impfile').click();
  $('#impfile').onchange = (e) => e.target.files[0] && importLogins(e.target.files[0]);
  const exportFile = (kind) => {
    if (!confirm('The exported file is NOT encrypted: anyone who gets it can read every password in it. Keep it somewhere safe and delete it when you are done.\n\nExport anyway?')) return;
    if (kind === 'csv') download('silk-export.csv', exportCsv(st.entries, now()), 'text/csv');
    else download('silk-export.json', exportJson(st.entries, now()), 'application/json');
  };
  $('#exp-csv').onclick = () => exportFile('csv');
  $('#exp-json').onclick = () => exportFile('json');
}

async function importLogins(file) {
  st.err = '';
  st.msg = '';
  try {
    if (file.size > MAX_FILE) throw new ImportError('That file is too large to import.');
    const { entries: found, skipped, passkeys } = importFile(await readFile(file));
    const next = st.entries.slice();
    let added = 0;
    for (const e of found) {
      if (next.some((x) => isLogin(x) && isLogin(e) && sameLogin(x, e))) continue;
      next.push(e);
      added++;
    }
    if (added) await persist(next);
    const dup = found.length - added;
    st.msg = `Imported ${added} item${added === 1 ? '' : 's'}${dup ? `, ${dup} already here` : ''}${skipped ? `, ${skipped} left out (trash or empty)` : ''}${passkeys ? `, ${passkeys} passkey${passkeys === 1 ? '' : 's'} can’t be copied` : ''}.`;
  } catch (e) {
    st.err = e instanceof ImportError || e instanceof VaultError ? e.message : 'Couldn’t import that file.';
  }
  render();
}

// ------------------------------------------------------------------ add and edit

/** Saves `entries` as the next revision, then pushes it to the cloud when signed in. */
async function persist(entries) {
  await exclusive(() => saveEntries(entries));
  st.entries = entries;
  if (st.cloud) {
    runSync('push', true).then((report) => {
      if (report === 'cloudNewer' || report === 'conflict') {
        st.msg = SYNC_MESSAGES[report];
        if (!st.edit && st.entries) renderMessages();
      }
    });
  }
}

function renderEdit() {
  const { e, isNew, show } = st.edit;
  const kind = e.kind || 'login';
  const input = (key, label, type = 'text', extra = '') => `<label class="field">${label}<input data-k="${key}" type="${type}" value="${esc(e[key])}" autocomplete="off" spellcheck="false" ${extra}></label>`;
  const custom = e.fields.map((f, i) => `<label class="field">${esc(f.label)}<span class="row"><input class="grow" data-f="${i}" type="${f.secret && !show ? 'password' : 'text'}" value="${esc(f.value)}" autocomplete="off" spellcheck="false">${f.value ? `<button class="small" data-copy-f="${i}" type="button">Copy</button>` : ''}</span></label>`).join('');
  const showLogin = kind === 'login';
  app.innerHTML = `
    <div class="row"><h1 class="grow">${isNew ? 'New item' : 'Edit item'}</h1><button class="link" id="cancel">Cancel</button></div>
    ${isNew ? `<label class="field">Kind<select id="kind">${NEW_KINDS.map(([k, n]) => `<option value="${k}" ${k === kind ? 'selected' : ''}>${n}</option>`).join('')}</select></label>` : `<p class="muted">${esc(kindName(e))}</p>`}
    ${input('title', 'Title')}
    ${showLogin ? input('username', 'Username or email') : ''}
    ${showLogin || kind === 'password' ? `<label class="field">Password<span class="row"><input class="grow" data-k="password" type="${show ? 'text' : 'password'}" value="${esc(e.password)}" autocomplete="new-password" spellcheck="false"><button class="small" id="gen" type="button">Generate</button></span></label>
      <div class="actions"><button class="small" id="toggle" type="button">${show ? 'Hide' : 'Show'} secrets</button>${e.password ? '<button class="small" id="cp" type="button">Copy password</button>' : ''}</div>` : (e.fields.some((f) => f.secret) ? `<div class="actions"><button class="small" id="toggle" type="button">${show ? 'Hide' : 'Show'} secrets</button></div>` : '')}
    ${showLogin ? input('url', 'Website', 'text', 'placeholder="https://example.com"') : ''}
    ${showLogin ? input('otp', 'One-time code secret or otpauth:// link') : ''}
    ${custom}
    <label class="field">Notes<textarea data-k="notes" rows="3">${esc(e.notes)}</textarea></label>
    <div id="messages">${messages()}</div>
    <div class="row"><button class="primary grow" id="save">Save</button>${isNew ? '' : '<button id="del">Delete</button>'}</div>`;
  const read = () => {
    app.querySelectorAll('[data-k]').forEach((el) => { e[el.dataset.k] = el.value; });
    app.querySelectorAll('[data-f]').forEach((el) => { e.fields[Number(el.dataset.f)].value = el.value; });
  };
  $('#cancel').onclick = () => {
    st.edit = null;
    st.err = '';
    render();
  };
  const kindSel = $('#kind');
  if (kindSel) {
    kindSel.onchange = () => {
      read();
      st.edit.e = blank(kindSel.value, { id: e.id, title: e.title, notes: e.notes });
      render();
    };
  }
  const tg = $('#toggle');
  if (tg) tg.onclick = () => { read(); st.edit.show = !show; render(); };
  const gen = $('#gen');
  if (gen) {
    gen.onclick = () => {
      read();
      e.password = generate(st.prefs.gen);
      st.edit.show = true;
      render();
    };
  }
  const cp = $('#cp');
  if (cp) cp.onclick = () => { read(); copy(e.password, 'Password'); };
  app.querySelectorAll('[data-copy-f]').forEach((b) => {
    b.onclick = () => { read(); copy(e.fields[Number(b.dataset.copyF)].value, e.fields[Number(b.dataset.copyF)].label); };
  });
  $('#save').onclick = async () => {
    read();
    st.err = '';
    st.msg = '';
    const otp = e.otp.trim();
    const label = otp && parseOtp(otp) ? otpLabel(otp) : { title: '', username: '' };
    const clean = { ...e, title: e.title.trim() || label.title, username: e.username.trim() || label.username, url: e.url.trim(), otp };
    if (!clean.title) st.err = 'Give it a title.';
    else if (clean.otp && !parseOtp(clean.otp)) st.err = 'That isn’t a valid one-time code secret or otpauth link.';
    if (st.err) return renderMessages();
    if (isNew && showLogin && !clean.username && !clean.password && !clean.url) {
      st.err = 'Add a username, password or website.';
      return renderMessages();
    }
    const next = isNew ? [...st.entries, clean] : st.entries.map((x) => (x.id === clean.id ? clean : x));
    $('#save').disabled = true;
    try {
      await persist(next);
      st.edit = null;
      st.msg = 'Saved.';
      render();
    } catch (err) {
      st.err = err instanceof VaultError ? err.message : 'Couldn’t save.';
      if (err instanceof VaultError && err.code === 'locked') st.entries = null;
      $('#save').disabled = false;
      renderMessages();
      if (!st.entries) render();
    }
  };
  const del = $('#del');
  if (del) {
    del.onclick = async () => {
      if (!confirm(`Delete “${e.title || 'this item'}”? This also deletes it from your account the next time it syncs.`)) return;
      try {
        await persist(st.entries.filter((x) => x.id !== e.id));
        st.edit = null;
        st.msg = 'Deleted.';
      } catch (err) {
        st.err = err instanceof VaultError ? err.message : 'Couldn’t delete.';
      }
      render();
    };
  }
}

await loadState();
render();
if (st.entries) backgroundSync();
