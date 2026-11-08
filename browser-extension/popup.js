import { parseOtp, totpCode, secondsLeft, groupCode } from './src/totp.js';
import { urlMatches, hostOf } from './src/match.js';
import { silkFill } from './src/fill.js';
import { toBase64, fromBase64, parseHeader, VaultError } from './src/vault.js';

const IDLE_MS = 5 * 60 * 1000; // same idle limit as the app
const MAX_FILE = 8 * 1024 * 1024; // chrome.storage.local allows 10 MB

const app = document.getElementById('app');
const st = { vault: null, header: null, name: '', entries: null, tab: 'logins', query: '', page: null, msg: '', err: '', busy: false, keyFile: null, keyName: '', progress: 0, timer: null };

// ------------------------------------------------------------------ small helpers

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const $ = (sel) => app.querySelector(sel);
const readFile = async (file) => new Uint8Array(await file.arrayBuffer());

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

async function loadState() {
  const { vault, vaultName } = await chrome.storage.local.get(['vault', 'vaultName']);
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
  if (!st.vault) return renderImport();
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

function renderImport() {
  app.innerHTML = `
    <h1>Silk</h1>
    <p>Add your vault to this browser. In the Android app open <b>More</b> and tap <b>Back up vault</b>, move the <code>.silk</code> file to this computer, then choose it here. It stays encrypted; only your master password opens it.</p>
    <input id="file" type="file" hidden>
    <button class="primary" id="pick">Choose vault file</button>
    <div id="messages">${messages()}</div>`;
  $('#pick').onclick = () => $('#file').click();
  $('#file').onchange = async (e) => {
    const f = e.target.files[0];
    if (f) await importVault(f);
  };
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
  } catch (e) {
    st.err = e instanceof VaultError ? e.message : 'Couldn’t read that file.';
  }
  render();
}

function renderUnlock() {
  const needsKey = st.header.keyFile;
  app.innerHTML = `
    <h1>Unlock vault</h1>
    <p class="muted">${esc(st.name)}</p>
    <input id="pw" type="password" placeholder="Master password" autocomplete="off" ${st.busy ? 'disabled' : ''}>
    ${needsKey ? `<div class="row"><span class="grow muted">${st.keyName ? esc(st.keyName) : 'This vault needs its key file'}</span>
      <input id="kf" type="file" hidden><button class="small" id="pickkey">Choose key file</button></div>` : ''}
    <button class="primary" id="go" ${st.busy ? 'disabled' : ''}>${st.busy ? `Unlocking… ${Math.round(st.progress * 100)}%` : 'Unlock'}</button>
    <div id="messages">${messages()}</div>
    <div class="row"><button class="link small" id="other">Use a different vault file</button></div>
    <input id="file" type="file" hidden>`;
  $('#pw').focus();
  $('#pw').onkeydown = (e) => { if (e.key === 'Enter') unlock(); };
  $('#go').onclick = unlock;
  $('#other').onclick = () => $('#file').click();
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
    <div class="row"><h1 class="grow">Silk</h1><button class="link" id="lock">Lock</button></div>
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
    <p class="muted">This is a copy of your phone’s vault. To update it, back up again in the app and add the new file.</p>`;
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
