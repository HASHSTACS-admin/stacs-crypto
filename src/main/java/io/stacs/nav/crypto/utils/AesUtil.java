//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package io.stacs.nav.crypto.utils;

import com.google.common.base.Charsets;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AesUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(AesUtil.class);
    public static final String ALGORITHM = "AES/ECB/ISO10126Padding";
    public static final String AES = "AES";

    public static byte[] generateKey() {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance(AES);
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            kgen.init(128, random);
            SecretKey original_key = kgen.generateKey();
            return original_key.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String generateHexKey() {
        return Hex.toHexString(generateKey());
    }

    public static byte[] encrypt(byte[] content, byte[] keys) throws GeneralSecurityException {
        SecretKey key = new SecretKeySpec(keys, AES);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] result = cipher.doFinal(content);
        return result;
    }

    public static byte[] decrypt(byte[] content, byte[] keys) throws GeneralSecurityException {
        SecretKey key = new SecretKeySpec(keys, AES);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] result = cipher.doFinal(content);
        return result;
    }

    public static byte[] encrypt(String content, String password) throws GeneralSecurityException {
        return encrypt(content.getBytes(Charsets.UTF_8), Hex.decode(password));
    }

    public static byte[] decrypt(String content, String password) throws GeneralSecurityException {
        return decrypt(Base64.decode(content), Hex.decode(password));
    }

    public static String encryptToString(String content, String password) throws GeneralSecurityException {
        byte[] encryptBytes = encrypt(content, password);
        if (null == encryptBytes) {
            return null;
        }
        return Base64.toBase64String(encryptBytes);
    }

    public static String decryptToString(String content, String password) throws GeneralSecurityException {
        byte[] decryptBytes = decrypt(content, password);
        return null == decryptBytes ? null : new String(decryptBytes, Charsets.UTF_8);
    }
}
