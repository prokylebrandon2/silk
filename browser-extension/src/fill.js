// Runs INSIDE the web page (chrome.scripting.executeScript serialises this function's source),
// so it must not refer to anything outside its own body.
export function silkFill(user, pass, code) {
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled && !el.readOnly;
  };
  const set = (el, v) => {
    // React and friends track the value through the native setter, so go through it.
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    desc.set.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const inputs = Array.from(document.querySelectorAll('input')).filter(visible);
  const textual = inputs.filter((i) => ['text', 'email', 'tel', 'search', ''].includes(i.type));
  const done = { user: false, pass: false, code: false };

  if (code) {
    const otp =
      inputs.find((i) => (i.autocomplete || '').includes('one-time-code')) ||
      textual.concat(inputs.filter((i) => i.type === 'number')).find((i) =>
        /otp|totp|2fa|mfa|verif|one.?time|security.?code|auth.?code|token/i.test(`${i.name} ${i.id} ${i.placeholder} ${i.getAttribute('aria-label') || ''}`));
    if (otp) {
      set(otp, code);
      done.code = true;
    }
    return done;
  }

  const ac = (i) => (i.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/);
  const pws = inputs.filter((i) => i.type === 'password');
  // The login's password field: marked current-password, else the first one not meant for choosing a new password.
  const pw = pws.find((i) => ac(i).includes('current-password')) || pws.find((i) => !ac(i).includes('new-password')) || pws[0];
  // A field the page itself marks as the user name or the email address.
  const marked = textual.find((i) => ac(i).includes('username')) || textual.find((i) => ac(i).includes('email') || i.type === 'email');
  if (pw && pass) {
    set(pw, pass);
    done.pass = true;
  }
  if (user) {
    let field = marked || null;
    if (field) {
      // the page marks it, so use it
    } else if (pw) {
      // The closest text field that comes before the password field in the page.
      for (const t of textual) {
        if (t.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING) field = t;
      }
    } else {
      field =
        textual.find((i) => /user|email|login|account/i.test(`${i.name} ${i.id} ${i.autocomplete}`)) || textual[0] || null;
    }
    if (field) {
      set(field, user);
      done.user = true;
    }
  }
  return done;
}
