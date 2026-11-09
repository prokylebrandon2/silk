package app.silk;

/** JNI entry points implemented in Rust (libsilk.so). */
public final class Native {
    static {
        System.loadLibrary("silk");
    }

    private Native() {}

    /** Autofill: a flattened description of the form in, a JSON decision out. */
    public static native String fill(String requestJson);

    /** Result of a document-picker request. status: 0 ok, 1 cancelled, 2 failed. data/name are null unless ok. */
    public static native void onFile(int code, int status, String name, byte[] data);

    /** Result of the QR scanner. status: 0 ok (text is the code's text), 1 cancelled, 2 failed. */
    public static native void onScan(int status, String text);

    /** The phone's Back button. True when the UI took it (it steps back, or calls exitApp from the first screen). */
    public static native boolean onBack();

    /** Wipes the unlocked vault from memory. */
    public static native void lock();

    static native void onBio(int op, int status, byte[] key);
}
