// The service worker. It locks an idle vault, keeps the cloud copy in step, and answers the autofill
// script that runs in web pages (src/autofill.js) and the fill shortcut. Everything with a secret in it
// stays here: the page script only ever hears titles and user names, and the password is put into the
// page by chrome.scripting after a real click, never sent to the page script.
import { urlMatches } from './src/match.js';
import { silkFill } from './src/fill.js';
import { isLogin } from './src/entry.js';
import { cloudSession, syncNow } from './src/cloud.js';
import { ensureUnlocked, touchSession, exclusive, reopenSession } from './src/state.js';

const SYNC_MINUTES = 30;

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'silk-lock') chrome.storage.session.remove('unlocked');
  if (alarm.name === 'silk-sync') backgroundSync();
});

/** Alarms don't survive a browser restart, so the sync alarm is set again, and the vault is brought up to date once. */
async function onStart() {
  if (await cloudSession()) {
    chrome.alarms.create('silk-sync', { periodInMinutes: SYNC_MINUTES });
    backgroundSync();
  }
}
chrome.runtime.onStartup.addListener(onStart);
chrome.runtime.onInstalled.addListener(onStart);

async function backgroundSync() {
  try {
    const { report } = await syncNow('sync');
    if (report === 'downloaded') await exclusive(reopenSession);
  } catch {
    // Offline or signed out: the popup says so when it is opened.
  }
}

// ------------------------------------------------------------------ autofill

/** Only secure pages get automatic offers: a password typed into plain http is open to everyone on the network. */
function pageOk(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || (u.protocol === 'http:' && u.hostname === 'localhost');
  } catch {
    return false;
  }
}

const byTitle = (a, b) => a.title.toLowerCase().localeCompare(b.title.toLowerCase());

/** The logins saved for this page, or null when the vault is locked. */
async function matchesFor(url) {
  const open = await ensureUnlocked();
  if (!open) return null;
  return open.entries.filter((e) => isLogin(e) && (e.username || e.password) && urlMatches(e.url, url)).sort(byTitle);
}

async function fillTab(tabId, e) {
  const [res] = await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: silkFill, args: [e.username, e.password, ''] });
  const r = res && res.result;
  return !!(r && (r.user || r.pass));
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  // Only this extension's own page script, in the top frame of a tab on a secure page.
  if (sender.id !== chrome.runtime.id || !sender.tab || sender.frameId !== 0 || !pageOk(sender.url) || !msg) return false;
  if (msg.type === 'autofill:list') {
    matchesFor(sender.url).then(
      (found) => reply(found ? { locked: false, items: found.slice(0, 5).map((e) => ({ id: e.id, title: e.title, username: e.username })) } : { locked: true, items: [] }),
      () => reply({ locked: true, items: [] }),
    );
    return true;
  }
  if (msg.type === 'autofill:fill') {
    // The id is looked up again among this page's own matches: a login for another site can never be asked for.
    matchesFor(sender.url)
      .then(async (found) => {
        const e = found && found.find((x) => x.id === msg.id);
        if (!e) return { ok: false };
        const ok = await fillTab(sender.tab.id, e);
        await touchSession();
        return { ok };
      })
      .then(reply, () => reply({ ok: false }));
    return true;
  }
  if (msg.type === 'autofill:unlock') {
    chrome.action.openPopup().catch(() => {});
  }
  return false;
});

// The shortcut: fill the one login that fits this page, or open the popup to choose.
chrome.commands.onCommand.addListener(async (command, tab) => {
  if (command !== 'fill-login' || !tab || !tab.url || !pageOk(tab.url)) return;
  try {
    const found = await matchesFor(tab.url);
    if (found && found.length === 1 && (await fillTab(tab.id, found[0]))) {
      await touchSession();
      return;
    }
  } catch {
    // fall through to the popup
  }
  chrome.action.openPopup().catch(() => {});
});
