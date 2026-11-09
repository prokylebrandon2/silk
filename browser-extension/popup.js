import { parseOtp, totpCode, secondsLeft, groupCode } from './src/totp.js';
import { urlMatches, hostOf } from './src/match.js';
import { silkFill } from './src/fill.js';
import { toBase64, fromBase64, parseHeader, joinBackup, VaultError } from './src/vault.js';

const IDLE_MS = 5 * 60 * 1000; // same idle limit as the app
const MAX_FILE = 8 * 1024 * 1024; // chrome.storage.local allows 10 MB

const app = document.getElementById('app');
const st = { vault: null, header: null, name: '', entries: null, tab: 'logins', query: '', page: null, msg: '', err: '', busy: false, keyFile: null, keyName: '', progress: 0, timer: null, view: '', cfg: null, email: '' };

// ------------------------------------------------------------------ small helpers

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const $ = (sel) => app.querySelector(sel);
const readFile = async (file) => new Uint8Array(await file.arrayBuffer());

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

async function loadState() {
  const { vault, vaultName, cloud } = await chrome.storage.local.get(['vault', 'vaultName', 'cloud']);
  st.cfg = cloud ? cloudConfig(cloud.url, cloud.key) : null;
  if (vault) {
    try {
      st.vault = fromBase64(vault);
      st.header = parseHeader(st.vault);
      st.name = vaultName || 'vault';
    } catch {
      st.vault = null;
    }
  }
  const { unlocked } = await chrome.storage.session.get('unlocked');
  if (unlocked && unlocked.until > Date.now() && st.vault) {
    st.entries = unlocked.entries;
    await touch();
  } else if (unlocked) {
    await chrome.storage.session.remove('unlocked');
  }
  const tab = await currentTab();
  st.page = tab && tab.url ? { id: tab.id, url: tab.url } : null;
}

async function touch() {
  if (!st.entries) return;
  const until = Date.now() + IDLE_MS;
  await chrome.storage.session.set({ unlocked: { entries: st.entries, until } });
  chrome.alarms.create('silk-lock', { when: until });
}

async function lock() {
  st.entries = null;
  st.query = '';
  st.msg = '';
  await chrome.storage.session.remove('unlocked');
  chrome.alarms.clear('silk-lock');
  render();
}

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    st.msg = `${what} copied. It stays on the clipboard until you copy something else.`;
  } catch {
    st.err = 'The browser refused to copy.';
  }
  await touch();
  renderMessages();
}

// ------------------------------------------------------------------ views

function render() {
  clearInterval(st.timer);
  st.timer = null;
  if (!st.vault || st.view === 'login') return renderLogin();
  if (!st.entries) return renderUnlock();
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
  app.innerHTML = `
    <div class="brand"><img src="icons/48.png" alt=""><h1>Silk</h1></div>
    <p>Sign in with your Silk cloud account to bring your vault to this browser. It stays encrypted; only your master password opens it.</p>
    <input id="email" type="email" placeholder="Account email" autocomplete="username" spellcheck="false" value="${esc(st.email)}" ${busy}>
    <input id="acct" type="password" placeholder="Account password" autocomplete="current-password" ${busy}>
    <button class="primary" id="signin" ${busy}>${st.busy ? 'Signing in…' : 'Sign in'}</button>
    <details ${st.cfg ? '' : 'open'}>
      <summary>Cloud project</summary>
      <input id="url" type="text" placeholder="https://your-project.supabase.co" spellcheck="false" value="${esc(st.cfg ? st.cfg.url : '')}">
      <input id="key" type="text" placeholder="Publishable key" spellcheck="false" value="${esc(st.cfg ? st.cfg.key : '')}">
      <p class="muted">The same two values as in the app’s <code>local.properties</code>. Only the publishable key belongs here, never a secret key.</p>
    </details>
    <div id="messages">${messages()}</div>
    <div class="or">or</div>
    <input id="file" type="file" hidden>
    <button id="pick">Choose a backup file</button>
    <p class="muted">In the Android app open <b>More</b> and tap <b>Back up vault</b>, move the <code>.silk</code> file to this computer, then choose it here.</p>
    ${st.vault ? '<div class="row"><button class="link small" id="back">Back to unlock</button></div>' : ''}`;
  const email = $('#email');
  const acct = $('#acct');
  email.oninput = () => { st.email = email.value; };
  email.onkeydown = acct.onkeydown = (e) => { if (e.key === 'Enter') signInCloud(); };
  $('#signin').onclick = signInCloud;
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
  (st.email ? acct : email).focus();
}

// ------------------------------------------------------------------ cloud sign-in
// The same two steps as the app (core/src/auth.rs, core/src/supabase.rs): Supabase Auth signs in with
// email and password, then the two encrypted files come from the user's folder in the private bucket.
// Only the project values and the finished backup are kept; neither the account password nor the
// session is stored. The content security policy lets this page talk to *.supabase.co and nothing else.

const clean = (s) => String(s).replace(/[\x00-\x1f\x7f]/g, '').slice(0, 160);

function jwtClaims(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(new TextDecoder().decode(fromBase64(b64 + '='.repeat((4 - (b64.length % 4)) % 4))));
  } catch {
    return null;
  }
}

/** Same rules as the app's Config::new: a Supabase project URL and a publishable key, never a secret one. */
function cloudConfig(url, key) {
  let base = String(url || '').trim().replace(/\/+$/, '');
  for (const api of ['/rest/v1', '/auth/v1', '/storage/v1']) {
    if (base.endsWith(api)) {
      base = base.slice(0, -api.length);
      break;
    }
  }
  const k = String(key || '').trim();
  if (!/^https:\/\/[a-z0-9]+\.supabase\.co$/.test(base)) return null;
  if (!k || k.startsWith('YOUR_') || k.startsWith('sb_secret_') || !/^[A-Za-z0-9._-]+$/.test(k)) return null;
  if (k.includes('.')) {
    const claims = jwtClaims(k);
    if (!claims || claims.role !== 'anon') return null;
  }
  return { url: base, key: k };
}

async function cloudCall(cfg, path, init, token) {
  const headers = { apikey: cfg.key, ...(init.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  try {
    return await fetch(cfg.url + path, { ...init, headers, credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(30000) });
  } catch {
    throw new VaultError('network', 'Couldn’t reach Supabase. Check your connection and the project URL.');
  }
}

function authError(status, body) {
  const code = String(body.error_code || '');
  const msg = String(body.msg || body.message || body.error_description || body.error || '');
  const lower = msg.toLowerCase();
  if (code === 'invalid_credentials' || body.error === 'invalid_grant' || lower.includes('invalid login credentials')) return 'Wrong email or password.';
  if (code === 'email_not_confirmed' || lower.includes('email not confirmed')) return 'Confirm your email first: open the link Supabase sent to that address, then sign in.';
  if (code === 'email_provider_disabled') return 'Email sign-in is turned off in the Supabase project.';
  if (code === 'user_banned') return 'This account has been disabled.';
  if (status === 429 || code.startsWith('over_')) return 'Too many attempts. Wait a few minutes and try again.';
  if (lower.includes('api key') || lower.includes('apikey')) return 'Supabase doesn’t accept that key. Check the publishable key.';
  return msg ? clean(msg) : `Supabase Auth answered ${status}`;
}

/** One file from the user's folder. `null` means it isn't there; every other problem throws. */
async function getObject(cfg, token, uid, name) {
  const res = await cloudCall(cfg, `/storage/v1/object/authenticated/silk-vaults/vaults/${encodeURIComponent(uid)}/${name}`, {}, token);
  if (res.ok) {
    if (Number(res.headers.get('content-length') || 0) > MAX_FILE) throw new VaultError('too-large', 'That vault is too large for this extension.');
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (bytes.length > MAX_FILE) throw new VaultError('too-large', 'That vault is too large for this extension.');
    return bytes;
  }
  // Storage sometimes answers 400 with the real status in the body.
  const err = await res.json().catch(() => ({}));
  const code = Number(err.statusCode || res.status);
  const msg = String(err.message || '');
  if (code === 401 || res.status === 401 || /jwt/i.test(msg)) throw new VaultError('account', 'Supabase didn’t accept the sign-in. Try again.');
  if (/bucket/i.test(msg)) throw new VaultError('cloud', `Supabase Storage: ${clean(msg)}`);
  if (code === 404 || err.error === 'not_found') return null;
  if (code === 403 || /row-level security/i.test(msg)) throw new VaultError('cloud', 'Supabase refused the request. Check that supabase/storage-policies.sql has been run on the project.');
  throw new VaultError('cloud', `Supabase Storage answered ${code}${msg ? `: ${clean(msg)}` : ''}`);
}

async function downloadVault(cfg, email, password) {
  const res = await cloudCall(cfg, '/auth/v1/token?grant_type=password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new VaultError('account', authError(res.status, body));
  const uid = body.user && body.user.id;
  const claims = jwtClaims(body.access_token);
  // Same check as the app: the token must belong to the account whose folder is read.
  if (!uid || !claims || claims.sub !== uid) throw new VaultError('account', 'Supabase gave an unexpected sign-in answer.');
  const slot = await getObject(cfg, body.access_token, uid, 'keyslot.skvk');
  if (!slot) throw new VaultError('no-vault', 'This account has no vault in the cloud yet. Open Silk on your phone and sync first.');
  const vault = await getObject(cfg, body.access_token, uid, 'vault.skln');
  if (!vault) throw new VaultError('no-vault', 'The cloud vault isn’t complete yet. Sync once more in the app, then try again.');
  return joinBackup(slot, vault);
}

async function signInCloud() {
  if (st.busy) return;
  const email = $('#email').value.trim();
  const password = $('#acct').value;
  const cfg = cloudConfig($('#url').value, $('#key').value);
  st.email = email;
  st.err = '';
  st.msg = '';
  if (!cfg) {
    st.err = 'Enter the project URL (https://<project>.supabase.co) and its publishable key. A secret key is not accepted.';
    return renderMessages();
  }
  if (!email || !password) {
    st.err = 'Enter the account email and password.';
    return renderMessages();
  }
  st.busy = true;
  const btn = $('#signin');
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  try {
    const bytes = await downloadVault(cfg, email, password);
    const name = `Cloud vault · ${email}`;
    await chrome.storage.local.set({ cloud: cfg, vault: toBase64(bytes), vaultName: name });
    st.cfg = cfg;
    st.header = parseHeader(bytes);
    st.vault = bytes;
    st.name = name;
    st.entries = null;
    await chrome.storage.session.remove('unlocked');
    st.view = '';
    st.msg = 'Vault downloaded. Enter its password to unlock it.';
    st.busy = false;
    return render();
  } catch (e) {
    st.err = e instanceof VaultError ? e.message : 'Couldn’t download the vault.';
    st.busy = false;
    btn.disabled = false;
    btn.textContent = 'Sign in';
    return renderMessages();
  }
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
    st.header = parseHeader(bytes);
    st.vault = bytes;
    st.name = file.name;
    await chrome.storage.local.set({ vault: toBase64(bytes), vaultName: file.name });
    st.entries = null;
    await chrome.storage.session.remove('unlocked');
    st.msg = 'Vault added. Enter its password to unlock it.';
    st.view = '';
  } catch (e) {
    st.err = e instanceof VaultError ? e.message : 'Couldn’t read that file.';
  }
  render();
}

function renderUnlock() {
  const needsKey = st.header.keyFile;
  app.innerHTML = `
    <div class="brand"><img src="icons/48.png" alt=""><h1>Unlock vault</h1></div>
    <p class="muted">${esc(st.name)}</p>
    <input id="pw" type="password" placeholder="Master password" autocomplete="off" ${st.busy ? 'disabled' : ''}>
    ${needsKey ? `<div class="row"><span class="grow muted">${st.keyName ? esc(st.keyName) : 'This vault needs its key file'}</span>
      <input id="kf" type="file" hidden><button class="small" id="pickkey">Choose key file</button></div>` : ''}
    <button class="primary" id="go" ${st.busy ? 'disabled' : ''}>${st.busy ? `Unlocking… ${Math.round(st.progress * 100)}%` : 'Unlock'}</button>
    <div id="messages">${messages()}</div>
    <div class="row"><button class="link small" id="cloud">Sign in to update</button><button class="link small" id="other">Use a different vault file</button></div>
    <input id="file" type="file" hidden>`;
  $('#pw').focus();
  $('#pw').onkeydown = (e) => { if (e.key === 'Enter') unlock(); };
  $('#go').onclick = unlock;
  $('#other').onclick = () => $('#file').click();
  $('#cloud').onclick = () => {
    if (st.busy) return;
    st.view = 'login';
    st.err = '';
    st.msg = '';
    render();
  };
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
  st.busy = true;
  st.err = '';
  st.msg = '';
  st.progress = 0;
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
    st.entries = ev.data.entries;
    st.keyFile = null;
    st.keyName = '';
    await touch();
    render();
  };
  worker.onerror = () => {
    worker.terminate();
    st.busy = false;
    st.err = 'Couldn’t unlock the vault in this browser.';
    render();
  };
  worker.postMessage({ file: st.vault, password: pw, keyFile: st.keyFile });
}

function renderMain() {
  app.innerHTML = `
    <div class="row"><div class="brand grow"><img src="icons/48.png" alt=""><h1>Silk</h1></div><button class="link" id="lock">Lock</button></div>
    <div class="tabs" role="tablist">
      <button role="tab" id="t-logins" aria-selected="${st.tab === 'logins'}">Logins</button>
      <button role="tab" id="t-codes" aria-selected="${st.tab === 'codes'}">Codes</button>
    </div>
    <div id="messages">${messages()}</div>
    <div id="body"></div>`;
  $('#lock').onclick = lock;
  $('#t-logins').onclick = () => { st.tab = 'logins'; render(); };
  $('#t-codes').onclick = () => { st.tab = 'codes'; render(); };
  if (st.tab === 'logins') renderLogins();
  else renderCodes();
}

function matches(e, q) {
  if (!q) return true;
  const s = q.toLowerCase();
  return e.title.toLowerCase().includes(s) || e.username.toLowerCase().includes(s) || e.url.toLowerCase().includes(s);
}

function itemHtml(e, here) {
  return `<div class="item" data-id="${esc(e.id)}">
    <div><div class="title">${esc(e.title || '(untitled)')}</div><div class="sub">${esc(e.username)}${e.url ? ` · ${esc(hostOf(e.url))}` : ''}</div></div>
    <div class="actions">
      ${st.page ? `<button class="small ${here ? 'primary' : ''}" data-act="fill">Fill</button>` : ''}
      ${e.username ? '<button class="small" data-act="user">Copy user</button>' : ''}
      ${e.password ? '<button class="small" data-act="pass">Copy password</button>' : ''}
      ${parseOtp(e.otp) ? '<button class="small" data-act="otp">Copy code</button>' : ''}
    </div></div>`;
}

function renderLogins() {
  const body = $('#body');
  const sorted = st.entries.slice().sort((a, b) => a.title.toLowerCase().localeCompare(b.title.toLowerCase()));
  const shown = sorted.filter((e) => matches(e, st.query));
  const here = st.page ? shown.filter((e) => urlMatches(e.url, st.page.url)) : [];
  const rest = shown.filter((e) => !here.includes(e));
  body.innerHTML = `
    <input id="q" type="search" placeholder="Search logins" value="${esc(st.query)}">
    <div class="list">
      ${here.length ? `<div class="section">This site</div>${here.map((e) => itemHtml(e, true)).join('')}` : ''}
      ${rest.length ? `<div class="section">${here.length ? 'All logins' : 'Logins'}</div>${rest.map((e) => itemHtml(e, false)).join('')}` : ''}
      ${shown.length ? '' : `<p>${st.query ? 'No logins match your search.' : 'This vault has no logins.'}</p>`}
    </div>
    <p class="muted">This is a copy of your phone’s vault. To update it, lock Silk and sign in again, or add a new backup file.</p>`;
  const q = $('#q');
  q.oninput = () => { st.query = q.value; const pos = q.selectionStart; renderLogins(); const n = $('#q'); n.focus(); n.setSelectionRange(pos, pos); touch(); };
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
    return p ? copy(await totpCode(p, Math.floor(Date.now() / 1000)), 'Code') : null;
  }
  if (what === 'fill') return fill(e, null);
  if (what === 'fillcode') return fill(e, await totpCode(parseOtp(e.otp), Math.floor(Date.now() / 1000)));
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
      st.msg = 'Filled.';
      await touch();
      renderMessages();
      return window.close();
    } else {
      st.err = 'No login form found on this page.';
    }
  } catch {
    st.err = 'The browser doesn’t allow filling this page.';
  }
  await touch();
  return renderMessages();
}

function renderCodes() {
  const body = $('#body');
  const withOtp = st.entries.map((e) => ({ e, p: parseOtp(e.otp) })).filter((x) => x.p).sort((a, b) => a.e.title.toLowerCase().localeCompare(b.e.title.toLowerCase()));
  if (!withOtp.length) {
    body.innerHTML = '<p>No logins in this vault have a one-time password secret yet. Add one in the app.</p>';
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
    const now = Math.floor(Date.now() / 1000);
    for (const [i, { p }] of withOtp.entries()) {
      const key = `${i}:${Math.floor(now / p.period)}`;
      let code = cache.get(i);
      if (!code || code.key !== key) {
        code = { key, text: await totpCode(p, now) };
        cache.set(i, code);
      }
      const row = body.querySelector(`.item[data-i="${i}"]`);
      if (!row) return;
      const left = secondsLeft(p, now);
      row.querySelector('.code').textContent = groupCode(code.text);
      row.querySelector('.bar > i').style.width = `${(left / p.period) * 100}%`;
      row.querySelector('.otp').classList.toggle('urgent', left <= 5);
    }
  };
  body.querySelectorAll('.item').forEach((row) => {
    const { e, p } = withOtp[Number(row.dataset.i)];
    row.querySelector('[data-act="copy"]').onclick = async () => copy(await totpCode(p, Math.floor(Date.now() / 1000)), 'Code');
    const f = row.querySelector('[data-act="fillcode"]');
    if (f) f.onclick = () => act('fillcode', e);
  });
  tick();
  st.timer = setInterval(tick, 500);
}

await loadState();
render();
