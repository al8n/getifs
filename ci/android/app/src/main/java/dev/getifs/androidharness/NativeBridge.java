package dev.getifs.androidharness;

/** Loads the cargo-ndk-built shim and exposes the native check. */
public final class NativeBridge {
    static {
        System.loadLibrary("getifs_android_harness");
    }

    private NativeBridge() {}

    /** Empty string on success, else a report of failed getifs calls. */
    public static native String runChecks();
}
