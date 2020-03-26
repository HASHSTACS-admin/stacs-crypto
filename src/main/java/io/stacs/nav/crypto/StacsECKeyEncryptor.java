package io.stacs.nav.crypto;

import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;

/**
 * @author suimi
 * @date 2020/3/26
 */
public class StacsECKeyEncryptor {

    public static final String ENCRYPT_ALGORITHM = "ECIESwithAES-CBC";

    public static byte[] encrypt(ECKey stacsECKey, byte[] content) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, stacsECKey.getPublicKey());
        return cipher.doFinal(content);
    }

    public static byte[] encrypt(String pubKey, byte[] content) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, ECKey.publicKeyFromBytes(Hex.decode(pubKey)));
        return cipher.doFinal(content);
    }

    public static byte[] decrypt(ECKey priKey, byte[] content) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, priKey.getPrivateKey());
        return cipher.doFinal(content);
    }

    public static byte[] decrypt(String priKey, byte[] content) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, ECKey.privateKeyFromBytes(Hex.decode(priKey)));
        return cipher.doFinal(content);
    }
}
