package io.stacs.nav.crypto;

import io.stacs.nav.crypto.utils.AesUtil;
import org.junit.Test;

import java.security.GeneralSecurityException;

/**
 * @author suimi
 * @date 2020/3/24
 */
public class AesUtilTest {

    @Test public void test() throws GeneralSecurityException {
        String key = "a8ea2ceaa84ace0b5ebd5e31c17d9290";
        String min = "asdfj";
        for (int i = 0; i < 10; i++) {
            long l = System.currentTimeMillis();
            String s = AesUtil.encryptToString(min, key);
            String s1 = AesUtil.decryptToString(s, key);
            assert min.equals(s1);
            System.out.println(s);
        }
    }

    @Test public void testGenerate() {
        for (int i = 0; i < 10; i++) {
            System.out.println(AesUtil.generateHexKey());
        }
    }
}
