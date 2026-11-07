package app.silk;

import android.app.NativeActivity;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.PersistableBundle;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.service.autofill.FillResponse;
import android.view.WindowManager;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillManager;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * NativeActivity plus the Android calls Rust can't make on its own: document picker results,
 * clipboard, autofill settings and returning an autofill result. Rust calls the public methods over JNI.
 */
public class SilkActivity extends NativeActivity {
    // Request codes, mirrored in app/src/ui.rs.
    static final int KEY_PICK = 1;
    static final int KEY_CREATE = 2;
    static final int BACKUP_OUT = 3;
    static final int BACKUP_IN = 4;
    static final int IMPORT_IN = 5;
    static final int EXPORT_CSV = 6;
    static final int EXPORT_JSON = 7;
    // Status passed to Native.onFile.
    static final int OK = 0;
    static final int CANCELLED = 1;
    static final int FAILED = 2;

    private static final int KEY_LIMIT = 1_000_000;
    private static final int FILE_LIMIT = 32_000_000;
    /** "SKEY" + version + 64-byte secret: the part of a Silk key file that is never rewritten (silk-core keyfile::HEAD_LEN). */
    private static final int KEY_HEAD = 69;

    private byte[] pendingData;

    @Override
    protected void onCreate(Bundle state) {
        // Blocks screenshots and the recent-apps thumbnail.
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        super.onCreate(state);
    }

    // ---- document picker ----

    public void pickFile(final int code) {
        runOnUiThread(() -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                    .addCategory(Intent.CATEGORY_OPENABLE)
                    .setType("*/*");
            if (code == KEY_PICK) {
                // Ask for write access too: a Silk key file gets the cloud sign-in saved into it.
                i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                        | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
            }
            startActivityForResult(i, code);
        });
    }

    public void createFile(final int code, final String name, final byte[] data) {
        pendingData = data;
        runOnUiThread(() -> {
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT)
                    .addCategory(Intent.CATEGORY_OPENABLE)
                    .setType(mimeFor(name))
                    .putExtra(Intent.EXTRA_TITLE, name);
            startActivityForResult(i, code);
        });
    }

    private static String mimeFor(String name) {
        String n = name == null ? "" : name.toLowerCase();
        if (n.endsWith(".csv")) return "text/csv";
        if (n.endsWith(".json")) return "application/json";
        return "application/octet-stream";
    }

    @Override
    protected void onActivityResult(int code, int result, Intent data) {
        super.onActivityResult(code, result, data);
        if (code < KEY_PICK || code > EXPORT_JSON) return;
        byte[] out = null;
        String name = null;
        int status = CANCELLED;
        if (result == RESULT_OK && data != null && data.getData() != null) {
            Uri uri = data.getData();
            try {
                boolean writing = code == KEY_CREATE || code == BACKUP_OUT || code == EXPORT_CSV || code == EXPORT_JSON;
                if (writing) {
                    out = pendingData;
                    if (out == null) throw new IllegalStateException("nothing to write");
                    try (OutputStream os = getContentResolver().openOutputStream(uri)) {
                        os.write(out);
                    }
                    if (code == EXPORT_CSV || code == EXPORT_JSON) {
                        // Plain-text export: wipe our copy and don't hand it back to Rust.
                        java.util.Arrays.fill(out, (byte) 0);
                        out = null;
                    }
                } else {
                    out = readAll(uri, code == KEY_PICK ? KEY_LIMIT : FILE_LIMIT); // IMPORT_IN and BACKUP_IN read a whole file
                }
                name = displayName(uri);
                if (code == KEY_PICK || code == KEY_CREATE) remember(uri);
                if (code == BACKUP_OUT || code == BACKUP_IN) rememberBackup(uri);
                status = OK;
            } catch (Exception e) {
                out = null;
                status = FAILED;
            }
        }
        pendingData = null;
        Native.onFile(code, status, name, out);
    }

    // ---- remembered key file (the location only; the file's bytes are never stored here) ----

    /** Reads and writes of the key file share one thread, so a read never overtakes a write still in flight. */
    private static final ExecutorService KEY_POOL = Executors.newSingleThreadExecutor();

    public void restoreKeyFile() {
        KEY_POOL.execute(() -> {
            String saved = prefs().getString("kf", null);
            if (saved == null) return;
            try {
                Uri uri = Uri.parse(saved);
                byte[] bytes = readAll(uri, KEY_LIMIT);
                Native.onFile(KEY_PICK, OK, displayName(uri), bytes);
            } catch (Exception e) {
                // moved, deleted or permission lost: the user chooses it again
            }
        });
    }

    /**
     * Saves the cloud sign-in into the remembered key file. {@code data} is the whole new file as built
     * by Rust. The key file is the one thing that can't be lost, so this is deliberately careful:
     * <ul>
     * <li>it only proceeds if the file on disk is a Silk key file whose first {@link #KEY_HEAD} bytes
     * (magic, version, secret) are byte-for-byte the same as in {@code data};</li>
     * <li>it never writes those bytes at all, only what follows them, then trims the file to size.</li>
     * </ul>
     * A crash or a provider that refuses the write can therefore damage at most the sign-in section,
     * which Rust ignores when it can't read it.
     */
    public void saveKeyFile(final byte[] data) {
        final String saved = prefs().getString("kf", null);
        if (saved == null || data == null || data.length < KEY_HEAD) return;
        KEY_POOL.execute(() -> {
            try {
                Uri uri = Uri.parse(saved);
                byte[] head = readHead(uri);
                if (head == null || !sameHead(head, data)) throw new IllegalStateException("not the same key file");
                try (ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(uri, "rw");
                     FileOutputStream fos = new FileOutputStream(pfd.getFileDescriptor());
                     FileChannel ch = fos.getChannel()) {
                    ch.position(KEY_HEAD);
                    ByteBuffer buf = ByteBuffer.wrap(data, KEY_HEAD, data.length - KEY_HEAD);
                    while (buf.hasRemaining()) ch.write(buf);
                    ch.truncate(data.length);
                    ch.force(true);
                }
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this,
                        "Couldn't save the cloud sign-in into your key file. You stay signed in until Silk closes.",
                        Toast.LENGTH_LONG).show());
            } finally {
                java.util.Arrays.fill(data, (byte) 0);
            }
        });
    }

    private byte[] readHead(Uri uri) throws Exception {
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) return null;
            byte[] head = new byte[KEY_HEAD];
            int off = 0;
            while (off < KEY_HEAD) {
                int n = in.read(head, off, KEY_HEAD - off);
                if (n < 0) return null;
                off += n;
            }
            return head;
        }
    }

    private static boolean sameHead(byte[] onDisk, byte[] wanted) {
        if (onDisk.length < KEY_HEAD || wanted.length < KEY_HEAD) return false;
        if (onDisk[0] != 'S' || onDisk[1] != 'K' || onDisk[2] != 'E' || onDisk[3] != 'Y') return false;
        for (int i = 0; i < KEY_HEAD; i++) {
            if (onDisk[i] != wanted[i]) return false;
        }
        return true;
    }

    public void forgetKeyFile() {
        prefs().edit().remove("kf").apply();
    }

    private SharedPreferences prefs() {
        return getSharedPreferences("silk", Context.MODE_PRIVATE);
    }

    private void remember(Uri uri) {
        try {
            // Read and write: a Silk key file keeps the cloud sign-in written into it.
            getContentResolver().takePersistableUriPermission(uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        } catch (Exception noWrite) {
            try {
                getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
            } catch (Exception ignored) {
                // provider doesn't support persistable permissions
            }
        }
        prefs().edit().putString("kf", uri.toString()).apply();
    }

    // ---- automatic backup: the encrypted vault file is copied to the file chosen with Backup or Restore ----

    private static final java.util.concurrent.ExecutorService BACKUP_POOL = java.util.concurrent.Executors.newSingleThreadExecutor();

    private void rememberBackup(Uri uri) {
        try {
            getContentResolver().takePersistableUriPermission(uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            prefs().edit().putString("bk", uri.toString()).apply();
        } catch (Exception e) {
            // no write access to that location: no automatic backup
            prefs().edit().remove("bk").apply();
        }
    }

    public void autoBackup(final byte[] data) {
        final String saved = prefs().getString("bk", null);
        if (saved == null || data == null || data.length == 0) return;
        BACKUP_POOL.execute(() -> {
            try (OutputStream os = getContentResolver().openOutputStream(Uri.parse(saved), "wt")) {
                if (os == null) throw new IllegalStateException("cannot open");
                os.write(data);
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "Automatic backup failed. Use Backup to choose the file again.", Toast.LENGTH_LONG).show());
            }
        });
    }

    private byte[] readAll(Uri uri, int limit) throws Exception {
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) throw new IllegalStateException("cannot open");
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) > 0) {
                buf.write(chunk, 0, n);
                if (buf.size() > limit) throw new IllegalStateException("too large");
            }
            if (buf.size() == 0) throw new IllegalStateException("empty");
            return buf.toByteArray();
        }
    }

    private String displayName(Uri uri) {
        try (Cursor c = getContentResolver().query(uri, new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                String s = c.getString(0);
                if (s != null) return s;
            }
        } catch (Exception ignored) {
            // fall through to the path segment
        }
        String last = uri.getLastPathSegment();
        return last != null ? last : "key file";
    }

    // ---- cloud (Firebase sign-in, Supabase storage): the protocol lives in Rust, Java only carries the HTTPS call ----

    /** One HTTPS request for Rust's cloud clients; see {@link Net} for the reply layout. Called on a worker thread. */
    public byte[] http(String method, String url, String headers, byte[] body) {
        return Net.request(method, url, headers, body, supabaseHost());
    }

    /** The Firebase web API key, the Supabase project URL and the Supabase publishable key, one per line. */
    public String cloudConfig() {
        return getString(R.string.firebase_api_key) + "\n" + getString(R.string.supabase_url) + "\n"
                + getString(R.string.supabase_publishable_key);
    }

    /** The one host Net may reach besides Firebase sign-in: the configured Supabase project, or null. */
    private String supabaseHost() {
        try {
            URL u = new URL(getString(R.string.supabase_url).trim());
            String host = u.getHost();
            return "https".equals(u.getProtocol()) && host != null && host.endsWith(".supabase.co") ? host : null;
        } catch (Exception e) {
            return null; // still a placeholder: Rust won't send anything either
        }
    }

    // ---- clipboard ----

    /** Marks the clip as sensitive (Android 13+) and clears it after 5 minutes. */
    public void copyToClipboard(final String text) {
        runOnUiThread(() -> {
            final ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("Silk", text);
            if (Build.VERSION.SDK_INT >= 33) {
                PersistableBundle extras = new PersistableBundle();
                extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
                clip.getDescription().setExtras(extras);
            }
            cm.setPrimaryClip(clip);
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                try {
                    ClipData cur = cm.getPrimaryClip();
                    CharSequence now = (cur != null && cur.getItemCount() > 0) ? cur.getItemAt(0).getText() : null;
                    if (now == null || text.contentEquals(now)) cm.clearPrimaryClip();
                } catch (Exception ignored) {
                    // clipboard not readable from the background on this Android version
                }
            }, 300_000);
        });
    }

    // ---- settings and state read by Rust ----

    public boolean autofillEnabled() {
        AutofillManager m = getSystemService(AutofillManager.class);
        return m != null && m.hasEnabledAutofillServices();
    }

    public void openAutofillSettings() {
        runOnUiThread(() -> {
            try {
                startActivity(new Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE,
                        Uri.parse("package:" + getPackageName())));
            } catch (Exception e) {
                try {
                    startActivity(new Intent(Settings.ACTION_SETTINGS));
                } catch (Exception ignored) {
                    // nothing more we can do
                }
            }
        });
    }

    /** The version name from the build, for example 1.0.0. */
    public String appVersion() {
        try {
            String v = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            return v == null ? "" : v;
        } catch (Exception e) {
            return "";
        }
    }

    public boolean isDark() {
        int mode = getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        return mode == Configuration.UI_MODE_NIGHT_YES;
    }

    /** True when this activity was started by the autofill "Unlock Silk" row. */
    public boolean isAutofillRequest() {
        return getIntent() != null && getIntent().hasExtra("silk_req");
    }

    // ---- autofill result ----

    /** After unlocking: asks Rust which logins match, returns them to the app that requested autofill, and closes. */
    @SuppressWarnings("deprecation")
    public void finishWithFill() {
        runOnUiThread(() -> {
            Intent in = getIntent();
            String req = in.getStringExtra("silk_req");
            ArrayList<AutofillId> ids = in.getParcelableArrayListExtra("silk_ids");
            FillResponse resp = (req == null || ids == null) ? null : AutofillSvc.responseFor(this, req, ids);
            if (resp == null) {
                Toast.makeText(this, "No saved login matches this site or app.", Toast.LENGTH_LONG).show();
                setResult(RESULT_CANCELED);
            } else {
                setResult(RESULT_OK, new Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, resp));
            }
            finish();
        });
    }

    private Bio bio;

    private synchronized Bio bio() {
        if (bio == null) bio = new Bio(this);
        return bio;
    }

    public boolean bioAvailable() { return bio().available(); }
    public boolean bioEnrolled() { return bio().enrolled(); }
    public void bioEnroll(byte[] key) { bio().enroll(key); }
    public void bioUnlock() { bio().unlock(); }
    public void bioDisable() { bio().disable(); }
}
