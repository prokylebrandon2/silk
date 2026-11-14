// What a saved item looks like, mirroring core/src/entry.rs: the kinds, the fields a new card or
// identity starts with, the list subtitle, and the rule that tells two logins apart.

/** The kinds of item, in the order the app numbers them. */
const KINDS = ['login', 'card', 'note', 'identity', 'password', 'other', 'folder'];

/** The kinds a new item can be started as here. */
export const NEW_KINDS = [
  ['login', 'Login'],
  ['note', 'Note'],
  ['card', 'Card'],
  ['identity', 'Identity'],
];

const kindOf = (e) => (KINDS.includes(e.kind) ? e.kind : 'login');

/** A missing or unknown kind is a login. */
export const isLogin = (e) => kindOf(e) === 'login';

export const kindName = (e) => {
  const k = kindOf(e);
  return k.charAt(0).toUpperCase() + k.slice(1);
};

/** A random 128-bit id as lowercase hex. */
export const newId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');

/** The fields a new card or identity starts with. Every other kind starts with none. */
function template(kind) {
  const field = (label, secret) => ({ label, value: '', secret });
  if (kind === 'card') {
    return [field('Cardholder name', false), field('Card number', true), field('Expiry date', false), field('Security code', true), field('PIN', true)];
  }
  if (kind === 'identity') {
    return ['Full name', 'Email', 'Phone', 'Address', 'City', 'State or region', 'Postal code', 'Country'].map((label) => field(label, false));
  }
  return [];
}

/** A new, empty item of this kind. A login keeps the app's default empty kind. */
export const blank = (kind = 'login', fill = {}) => ({
  id: newId(),
  title: '',
  username: '',
  password: '',
  url: '',
  otp: '',
  notes: '',
  kind: kind === 'login' ? '' : kind,
  folder: '',
  fields: template(kind),
  ...fill,
});

const fieldValue = (e, label) => (e.fields.find((f) => f.label === label) || { value: '' }).value;

/** The second line of an item in the list: what tells it apart from the others of its kind. */
export function subtitle(e) {
  const kind = kindOf(e);
  if (kind === 'login') return e.username;
  if (kind === 'card') {
    const digits = fieldValue(e, 'Card number').replace(/\D/g, '');
    return digits.length < 4 ? '' : `•••• ${digits.slice(-4)}`;
  }
  if (kind === 'note') return (e.notes.split('\n')[0] || '').trim();
  if (kind === 'identity') return fieldValue(e, 'Full name') || fieldValue(e, 'Email');
  return '';
}

const same = (a, b) => a.trim().toLowerCase() === b.trim().toLowerCase();

/** The app's duplicate rule for imports: same title, username, website and password. */
export const sameLogin = (a, b) => same(a.title, b.title) && same(a.username, b.username) && same(a.url, b.url) && a.password === b.password;
