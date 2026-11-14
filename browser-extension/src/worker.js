// Argon2 takes a few seconds, so the unlock runs here and the popup stays responsive.
import { unlockVault, VaultError } from './vault.js';

self.onmessage = async (ev) => {
  const { file, password, keyFile } = ev.data;
  try {
    const { entries, vek, revision } = await unlockVault(file, password, keyFile, (f) => self.postMessage({ progress: f }));
    self.postMessage({ entries, vek, revision: revision.toString() });
  } catch (e) {
    self.postMessage({ error: e instanceof VaultError ? { code: e.code, message: e.message } : { code: 'failed', message: 'Couldn’t open the vault.' } });
  }
};
