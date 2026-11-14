// Moving logins in and out as plain files: Proton Pass exports (JSON and CSV) and any CSV with the
// usual login columns. Mirrors core/src/transfer.rs. The files this module reads and writes are NOT
// encrypted; the caller decides where they go and tells the user.
//
// Proton Pass JSON: {"vaults": {id: {"name", "items": [{"data": {"type", "metadata": {"name", "note"},
// "content": {...}}, "state"}]}}}. Proton Pass CSV: type,name,url,email,username,password,note,totp,createTime,modifyTime,vault
import { blank, newId } from './entry.js';

export class ImportError extends Error {
  constructor(message) {
    super(message);
    this.code = 'import';
  }
}

const bad = (m) => new ImportError(m);

/**
 * Reads a Proton Pass JSON or CSV export (or a generic login CSV).
 * Returns { entries, skipped, passkeys }: items left out (in the trash, empty), and passkeys that can't be copied.
 */
export function importFile(bytes) {
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) throw bad('This is a .zip file. Unzip it and choose the Data.json inside.');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw bad("This file isn't text. Choose a JSON or CSV export.");
  }
  text = text.replace(/^﻿+/, '');
  const head = text.trimStart();
  if (head.startsWith('-----BEGIN PGP')) throw bad('This export is encrypted. In Proton Pass export again without encryption.');
  return head.startsWith('{') ? importJson(head) : importCsv(text);
}

// ---------------------------------------------------------------- shared helpers

/** A trimmed string field, or "". */
const text = (v) => (typeof v === 'string' ? v.trim() : '');
/** A string field exactly as stored (passwords and notes keep their whitespace). */
const raw = (v) => (typeof v === 'string' ? v : '');
const hostPart = (url) => (url.includes('://') ? url.split('://').slice(1).join('://') : url).split('/')[0];

const appendLines = (notes, lines) => lines.reduce((n, l) => (n ? `${n}\n${l}` : l), notes);

/** "cardholderName" -> "Cardholder name". */
function humanize(key) {
  let out = '';
  Array.from(key).forEach((c, i) => {
    if (i === 0) out += c.toUpperCase();
    else if (c !== c.toLowerCase()) out += ` ${c.toLowerCase()}`;
    else out += c;
  });
  return out;
}

/** The simple text and number fields of a Proton item that isn't a login (cards, identities), as note lines. */
function flatten(content) {
  const lines = [];
  if (content && typeof content === 'object' && !Array.isArray(content)) {
    for (const [k, v] of Object.entries(content)) {
      const t = typeof v === 'string' ? v.trim() : typeof v === 'number' ? String(v) : '';
      if (t) lines.push(`${humanize(k)}: ${t}`);
    }
  }
  return lines;
}

function extraFields(data) {
  if (!Array.isArray(data.extraFields)) return [];
  const lines = [];
  for (const f of data.extraFields) {
    const name = text(f && f.fieldName);
    const d = f && f.data;
    const value = d && text(typeof d.content === 'string' ? d.content : d.totpUri);
    if (name && value) lines.push(`${name}: ${value}`);
  }
  return lines;
}

function makeLogin(title, emailIn, usernameIn, password, urls, totp, note) {
  const email = emailIn.trim();
  const username = usernameIn.trim();
  const login = email === '' ? username : email;
  const extra = [];
  if (email && username && email.toLowerCase() !== username.toLowerCase()) extra.push(`Username: ${username}`);
  if (urls.length > 1) extra.push(`Other websites: ${urls.slice(1).join(', ')}`);
  const url = urls[0] || '';
  const name = title.trim() || (url ? hostPart(url) : '') || login || 'Untitled';
  return blank('login', { title: name, username: login, password, url, otp: totp.trim(), notes: appendLines(note, extra) });
}

// ---------------------------------------------------------------- JSON import

function importJson(source) {
  let root;
  try {
    root = JSON.parse(source);
  } catch {
    throw bad("That JSON file couldn't be read.");
  }
  if (root && root.encrypted === true) throw bad('This export is encrypted. In Proton Pass export again without encryption.');
  const vaults = root && root.vaults;
  if (!vaults || typeof vaults !== 'object' || Array.isArray(vaults)) throw bad("This doesn't look like a Proton Pass export.");
  const out = { entries: [], skipped: 0, passkeys: 0 };
  for (const vault of Object.values(vaults)) {
    if (!vault || !Array.isArray(vault.items)) continue;
    for (const item of vault.items) {
      const entry = jsonItem(item, out);
      if (entry) out.entries.push(entry);
      else out.skipped += 1;
    }
  }
  return out;
}

function jsonItem(item, counts) {
  if (!item || item.state === 2) return null; // in the trash
  const data = item.data;
  const meta = data && data.metadata;
  if (!data || !meta) return null;
  const kind = typeof data.type === 'string' ? data.type : '';
  const content = data.content;
  const title = text(meta.name);
  const note = raw(meta.note);
  const extras = extraFields(data);

  if (kind === 'login') {
    if (!content) return null;
    const urls = (Array.isArray(content.urls) ? content.urls : []).filter((u) => typeof u === 'string').map((u) => u.trim()).filter(Boolean);
    const email = text(content.itemEmail);
    let user = text(content.itemUsername);
    if (!user && !email) user = text(content.username); // older exports
    if (Array.isArray(content.passkeys)) counts.passkeys += content.passkeys.length;
    const e = makeLogin(title, email, user, raw(content.password), urls, text(content.totpUri), note);
    e.notes = appendLines(e.notes, extras);
    return e;
  }

  // Notes, aliases, cards, identities: kept as an entry whose notes hold the fields.
  const lines = flatten(content).concat(extras);
  const username = kind === 'alias' ? text(item.aliasEmail) : '';
  if (!title && !note.trim() && lines.length === 0 && !username) return null;
  return blank('login', { title: title || humanize(kind || 'item'), username, notes: appendLines(note, lines) });
}

// ---------------------------------------------------------------- CSV

/** RFC 4180: quoted fields, doubled quotes, commas and line breaks inside quotes, CRLF or LF. */
function parseCsv(source) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (quoted) {
      if (c === '"') {
        if (source[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"' && field === '') {
      quoted = true;
    } else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n') {
      row.push(field);
      field = '';
      rows.push(row);
      row = [];
    } else if (c !== '\r') {
      field += c;
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

const findCol = (header, names) => {
  for (const n of names) {
    const i = header.indexOf(n);
    if (i >= 0) return i;
  }
  return -1;
};

function importCsv(source) {
  const rows = parseCsv(source).filter((r) => !r.every((c) => c.trim() === ''));
  if (rows.length === 0) throw bad('That file is empty.');
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const col = {
    title: findCol(header, ['name', 'title']),
    url: findCol(header, ['url', 'login_uri', 'website', 'login url', 'uri']),
    email: findCol(header, ['email']),
    user: findCol(header, ['username', 'login_username', 'user name']),
    pass: findCol(header, ['password', 'login_password']),
    note: findCol(header, ['note', 'notes', 'extra']),
    totp: findCol(header, ['totp', 'login_totp', 'otp']),
  };
  if (col.title < 0 && col.url < 0 && col.user < 0 && col.pass < 0 && col.email < 0) {
    throw bad("Couldn't find login columns (name, url, username, password) in this CSV.");
  }
  const out = { entries: [], skipped: 0, passkeys: 0 };
  for (const row of rows.slice(1)) {
    const get = (i) => (i >= 0 && row[i] !== undefined ? row[i] : '');
    const urls = get(col.url).split(/\s+/).filter(Boolean);
    out.entries.push(makeLogin(get(col.title), get(col.email), get(col.user), get(col.pass), urls, get(col.totp), get(col.note)));
  }
  return out;
}

const csvField = (s) => (/[,"\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);

// ---------------------------------------------------------------- export

/** Percent-encodes like core/src/transfer.rs: only letters, digits and - _ . ~ stay as they are. */
const pctEncode = (s) =>
  Array.from(new TextEncoder().encode(s), (b) => (/[A-Za-z0-9\-_.~]/.test(String.fromCharCode(b)) ? String.fromCharCode(b) : `%${b.toString(16).toUpperCase().padStart(2, '0')}`)).join('');

/** The one-time-password field as an otpauth:// link, which is what Proton Pass stores. */
function otpUri(e) {
  const o = e.otp.trim();
  if (!o) return '';
  if (o.toLowerCase().startsWith('otpauth://')) return o;
  const secret = o.replace(/[ \-=]/g, '').toUpperCase();
  if (!secret) return '';
  return `otpauth://totp/${pctEncode(e.title || 'Silk')}?secret=${secret}&algorithm=SHA1&digits=6&period=30`;
}

const isNote = (e) => !e.password && !e.username && !e.url.trim() && !e.otp.trim();

/** The note column of an export. Cards, identities and other items keep their labelled fields as lines of the note. */
const exportNote = (e) =>
  appendLines(
    e.notes,
    e.fields.filter((f) => f.value).map((f) => `${f.label}: ${f.value}`),
  );

/** Proton Pass splits the login into an email and a username column. */
const splitLogin = (username) => (username.includes('@') ? [username, ''] : ['', username]);

/** CSV in Proton Pass's own column layout. `now` is a Unix time in seconds. */
export function exportCsv(entries, now) {
  let out = 'type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n';
  for (const e of entries) {
    if (e.kind === 'folder') continue;
    const [email, user] = splitLogin(e.username);
    const cols = [isNote(e) ? 'note' : 'login', e.title, e.url, email, user, e.password, exportNote(e), otpUri(e), String(now), String(now), 'Silk'];
    out += `${cols.map(csvField).join(',')}\n`;
  }
  return out;
}

/** JSON in the shape of a Proton Pass export. `now` is a Unix time in seconds. */
export function exportJson(entries, now) {
  const share = newId();
  const items = entries
    .filter((e) => e.kind !== 'folder')
    .map((e) => {
      const [email, user] = splitLogin(e.username);
      const note = isNote(e);
      const content = note ? {} : { itemEmail: email, itemUsername: user, password: e.password, urls: e.url.trim() ? [e.url.trim()] : [], totpUri: otpUri(e), passkeys: [] };
      return {
        itemId: newId(),
        shareId: share,
        data: { metadata: { name: e.title, note: exportNote(e), itemUuid: newId() }, extraFields: [], type: note ? 'note' : 'login', content },
        state: 1,
        aliasEmail: null,
        contentFormatVersion: 1,
        createTime: now,
        modifyTime: now,
        pinned: false,
      };
    });
  return JSON.stringify({ version: '1.0.0', userId: 'silk', encrypted: false, vaults: { [share]: { name: 'Silk', description: 'Exported from Silk', items } } }, null, 2);
}
