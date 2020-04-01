package io.stacs.nav.crypto;

import com.google.common.base.Charsets;
import io.stacs.nav.crypto.jce.SpongyCastleProvider;
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

    @Test public void test2() throws GeneralSecurityException {
        StacsECKey.fromPrivate(Hex.decode("bbb43be030237c818bea2a5b808e872f432d1e83e6776f88b66a30d00956188c"));
        SpongyCastleProvider.getInstance();
        byte[] encrypt = StacsECKeyEncryptor.encrypt(
            "04ba98bf34af47145cf552b710570538b37bf3eff124e51c3361d02ea128c0447737be86077667feaca6dbc0679ae0653c4887d328a2b9d6d7f777599c287bf054",
            "a8ea2ceaa84ace0b5ebd5e31c17d9290".getBytes(Charsets.UTF_8));
        System.out.println("encrypt = " + Hex.toHexString(encrypt));

    }

}
