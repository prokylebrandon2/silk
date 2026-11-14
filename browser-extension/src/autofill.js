// The autofill script that runs in web pages (a content script, so it is a plain script and cannot import).
// It looks for a login form, asks the service worker which saved logins fit this page and shows a small
// menu next to the password field. It only ever hears titles and user names: the password is put into the
// page by the service worker after a real click here, never sent to this script. The menu lives in a closed
// shadow root, so the page's own scripts cannot read it or click it.
(() => {
  if (window.top !== window || window.__silkAutofill) return;
  window.__silkAutofill = true;

  const secure = location.protocol === 'https:' || (location.protocol === 'http:' && location.hostname === 'localhost');
  if (!secure) return;

  let host = null;
  let root = null;
  let anchor = null;
  let timer = 0;
  let dismissed = false;

  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled && !el.readOnly;
  };

  /** The password field of the first login form on the page that is showing. */
  const passwordField = () => Array.from(document.querySelectorAll('input[type=password]')).find(visible) || null;

  const send = (msg) =>
    new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (r) => resolve(chrome.runtime.lastError ? null : r));
      } catch {
        resolve(null); // the extension was reloaded: this script is orphaned
      }
    });

  function close() {
    if (host) host.remove();
    host = root = anchor = null;
  }

  function place() {
    if (!host || !anchor || !anchor.isConnected) return close();
    const r = anchor.getBoundingClientRect();
    host.style.cssText = `all:initial;position:fixed;z-index:2147483647;left:${Math.max(4, r.left)}px;top:${r.bottom + 4}px;width:${Math.max(220, Math.min(r.width, 320))}px`;
  }

  const css = `
    .menu { font: 13px/1.35 system-ui, sans-serif; background: #fff; color: #262626; border: 1px solid #d4d4d4; border-radius: 10px;
      box-shadow: 0 6px 20px rgba(0,0,0,.18); overflow: hidden; }
    @media (prefers-color-scheme: dark) { .menu { background: #262625; color: #e5e5e4; border-color: #454544; } }
    button { all: unset; box-sizing: border-box; display: block; width: 100%; padding: 8px 12px; cursor: pointer; }
    button:hover, button:focus-visible { background: rgba(127,127,127,.18); }
    .t { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .s { opacity: .7; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .h { opacity: .6; font-size: 11px; padding: 6px 12px 2px; letter-spacing: .04em; text-transform: uppercase; }`;

  function show(field, items, locked) {
    close();
    anchor = field;
    host = document.createElement('div');
    root = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = css;
    const menu = document.createElement('div');
    menu.className = 'menu';
    const head = document.createElement('div');
    head.className = 'h';
    head.textContent = 'Silk';
    menu.append(head);
    const add = (title, sub, onclick) => {
      const b = document.createElement('button');
      const t = document.createElement('div');
      t.className = 't';
      t.textContent = title;
      b.append(t);
      if (sub) {
        const s = document.createElement('div');
        s.className = 's';
        s.textContent = sub;
        b.append(s);
      }
      // A click the page made up with dispatchEvent is not trusted; only a real one fills.
      b.addEventListener('click', (e) => {
        if (e.isTrusted) onclick();
      });
      menu.append(b);
    };
    if (locked) {
      add('Unlock Silk', 'Open the vault to fill this login', () => {
        send({ type: 'autofill:unlock' });
        close();
      });
    } else {
      for (const it of items) {
        add(it.title || '(untitled)', it.username, async () => {
          close();
          await send({ type: 'autofill:fill', id: it.id });
        });
      }
    }
    root.append(style, menu);
    document.documentElement.append(host);
    place();
  }

  async function check() {
    timer = 0;
    if (dismissed) return;
    const field = passwordField();
    if (!field) return close();
    if (anchor === field && host) return place();
    const found = await send({ type: 'autofill:list' });
    if (!found || (!found.locked && !found.items.length)) return;
    // The field may have gone while the worker answered.
    const now = passwordField();
    if (now !== field || document.activeElement !== field) {
      field.addEventListener('focus', () => schedule(), { once: true });
      return;
    }
    show(field, found.items, found.locked);
  }

  function schedule() {
    if (!timer) timer = setTimeout(check, 250);
  }

  document.addEventListener('focusin', (e) => {
    if (e.target instanceof HTMLInputElement && e.target.type === 'password') schedule();
  });
  document.addEventListener('pointerdown', (e) => {
    if (host && e.composedPath()[0] !== host && !e.composedPath().includes(host) && e.target !== anchor) close();
  }, true);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && host) {
      dismissed = true;
      close();
    }
  });
  window.addEventListener('scroll', place, true);
  window.addEventListener('resize', place);
  // Single-page sites build their login form after load.
  new MutationObserver(() => {
    if (!host && document.activeElement instanceof HTMLInputElement && document.activeElement.type === 'password') schedule();
  }).observe(document.documentElement, { childList: true, subtree: true });
  if (document.activeElement instanceof HTMLInputElement && document.activeElement.type === 'password') schedule();
})();
