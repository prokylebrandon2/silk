package app.silk;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * The only network code in the app: one HTTPS request at a time for Rust's Firebase sign-in
 * (silk-core/src/firebase.rs) and Supabase Storage client (silk-core/src/supabase.rs). It holds no
 * logic. The URL, headers and body are built in Rust; this only refuses anything that isn't HTTPS to
 * the two Firebase sign-in hosts or the one Supabase project host from the app's configuration, so a
 * bug elsewhere can't turn it into a general-purpose downloader.
 *
 * Reply: two bytes of HTTP status (big-endian), then the response body. Status 0 means no answer
 * at all, and the body is a short reason.
 */
final class Net {
    private static final Set<String> HOSTS = new HashSet<>(Arrays.asList(
            "identitytoolkit.googleapis.com",
            "securetoken.googleapis.com"));
    /** More than the 20 MB the storage rules allow, so a legitimate vault always fits. */
    private static final int LIMIT = 32_000_000;

    private Net() {}

    /**
     * @param headers "Name: value" lines separated by \n
     * @param storageHost the Supabase project host from the configuration, or null when cloud sync isn't set up
     */
    static byte[] request(String method, String url, String headers, byte[] body, String storageHost) {
        HttpURLConnection c = null;
        try {
            URL u = new URL(url);
            boolean hostOk = HOSTS.contains(u.getHost()) || (storageHost != null && storageHost.equals(u.getHost()));
            if (!"https".equals(u.getProtocol()) || !hostOk || u.getUserInfo() != null || u.getPort() != -1) {
                return failure("blocked address");
            }
            c = (HttpURLConnection) u.openConnection();
            c.setRequestMethod(method);
            c.setConnectTimeout(10_000);
            c.setReadTimeout(30_000);
            c.setInstanceFollowRedirects(false);
            c.setUseCaches(false);
            if (headers != null) {
                for (String line : headers.split("\n")) {
                    int i = line.indexOf(':');
                    if (i > 0) c.setRequestProperty(line.substring(0, i).trim(), line.substring(i + 1).trim());
                }
            }
            if (body != null && body.length > 0) {
                c.setDoOutput(true);
                c.setFixedLengthStreamingMode(body.length);
                try (OutputStream os = c.getOutputStream()) {
                    os.write(body);
                }
            }
            int status = c.getResponseCode();
            InputStream in = status >= 400 ? c.getErrorStream() : c.getInputStream();
            byte[] data = in == null ? new byte[0] : readLimited(in);
            return pack(status, data);
        } catch (Exception e) {
            boolean offline = e instanceof UnknownHostException || e instanceof ConnectException
                    || e instanceof SocketTimeoutException || e instanceof NoRouteToHostException;
            return failure(offline ? "no network connection" : e.getClass().getSimpleName());
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private static byte[] readLimited(InputStream in) throws Exception {
        try (InputStream src = in) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = src.read(chunk)) > 0) {
                buf.write(chunk, 0, n);
                if (buf.size() > LIMIT) throw new IllegalStateException("too large");
            }
            return buf.toByteArray();
        }
    }

    private static byte[] pack(int status, byte[] data) {
        byte[] out = new byte[data.length + 2];
        out[0] = (byte) (status >> 8);
        out[1] = (byte) status;
        System.arraycopy(data, 0, out, 2, data.length);
        return out;
    }

    private static byte[] failure(String why) {
        return pack(0, why.getBytes(StandardCharsets.UTF_8));
    }
}
