package io.stacs.nav.crypto.utils;

import com.google.common.base.Charsets;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Longs;
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

    public static String generate40TxId(String originalTxId) {
        byte[] txIdBytes = originalTxId.getBytes();
        byte[] bytes = Longs.toByteArray(System.currentTimeMillis());
        byte[] txIdHash256 = HashUtil.twiceSha256(txIdBytes);
        byte[] result = new byte[20];
        System.arraycopy(bytes, 0, result, 0, bytes.length);
        System.arraycopy(txIdHash256, 0, result, bytes.length, 20 - bytes.length);
        return Hex.toHexString(result);
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
