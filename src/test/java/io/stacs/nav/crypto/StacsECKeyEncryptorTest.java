package io.stacs.nav.crypto;

import com.google.common.base.Charsets;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.security.GeneralSecurityException;

/**
 * @author suimi
 * @date 2020/3/26
 */
public class StacsECKeyEncryptorTest {

    @Test public void testEncrypt() throws GeneralSecurityException {

        String txt = "04992f7274f3cf93c6bf7f7a8fcb37a0527459854301f7cd881d6f46683a3904819862de77340c1a820be08a9e48";
        StacsECKey ecKey = new StacsECKey();
        byte[] txtBytes = txt.getBytes(Charsets.UTF_8);
        long startTime = System.currentTimeMillis();
        int size = 10;
        long min = 0, max = 0;
        for (int i = 0; i < size; i++) {
            long st = System.currentTimeMillis();
            byte[] bytes = StacsECKeyEncryptor.encrypt(ecKey, txtBytes);
            System.out.println("bytes = " + Hex.toHexString(bytes));
            byte[] result = StacsECKeyEncryptor.decrypt(ecKey, bytes);
            assert Arrays.areEqual(txtBytes, result);
            long cost = System.currentTimeMillis() - st;
            min = min == 0 ? cost : cost < min ? cost : min;
            max = max == 0 ? cost : cost > max ? cost : max;
        }
        System.out.println("min = " + min);
        System.out.println("max = " + max);
        System.out.println("avg = " + ((System.currentTimeMillis() - startTime) / size));
    }

}
