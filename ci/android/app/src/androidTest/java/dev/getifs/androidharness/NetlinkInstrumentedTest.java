package dev.getifs.androidharness;

import static org.junit.Assert.assertEquals;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Runs in the app process (untrusted_app SELinux domain). With the pre-fix
 * eager netlink bind() this fails with PermissionDenied; the autobind fix
 * makes the calls succeed, so runChecks() returns "".
 */
@RunWith(AndroidJUnit4.class)
public class NetlinkInstrumentedTest {
    @Test
    public void getifsCallsSucceedInAppSandbox() {
        String errors = NativeBridge.runChecks();
        assertEquals("getifs calls must succeed in the app sandbox", "", errors);
    }
}
