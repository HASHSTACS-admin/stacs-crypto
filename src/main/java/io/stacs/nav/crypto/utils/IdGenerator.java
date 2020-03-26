package io.stacs.nav.crypto.utils;

import com.google.common.base.Charsets;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Created by young001 on 2017/6/15.
 */
public class IdGenerator {

    /**
     * Generate random req id string.
     *
     * @return the string
     */
    @SuppressWarnings("deprecation") public static final String generateRandomReqId() {
        String requestId = null;
        UUID uuid = UUID.randomUUID();
        long timeMs = System.currentTimeMillis();
        String randomString = uuid.toString() + timeMs;
        HashFunction md5 = Hashing.md5();
        HashCode randomHashCode = md5.hashString(randomString, Charsets.UTF_8);
        requestId = new StringBuffer("reqid-").append(timeMs).append("-").append(randomHashCode.toString()).toString();
        return requestId;
    }

    /**
     * Generate pp id string.
     *
     * @param requestBiz the request biz
     * @param identity   the identity
     * @return the string
     */
    @SuppressWarnings("deprecation") public static final String generatePPId(String requestBiz, String identity) {
        String ppIdString = "unipassport_ppid_generator" + requestBiz + identity;
        HashFunction md5 = Hashing.md5();
        HashCode ppIdHashCode = md5.hashString(ppIdString, Charsets.UTF_8);
        return ppIdHashCode.toString();
    }

    public static String generate64TxId(String originalTxId) {
        byte[] txIdBytes = originalTxId.getBytes();
        byte[] txIdHash256 = twiceSha256(txIdBytes);
        return new String(Hex.encode(txIdHash256));
    }

    public static byte[] twiceSha256(byte[] input) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        digest.update(input, 0, input.length);
        return digest.digest(digest.digest());
    }

    /**
     * The entry point of application.
     *
     * @param args the input arguments
     */
    public static void main(String[] args) {
        System.out.println(generateRandomReqId());
    }
}
