package io.stacs.nav.crypto.utils;

import com.google.common.base.Charsets;
import com.google.common.base.Function;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

/**
 * @author suimi
 * @date 2020/4/3
 */
public class HashUtilTest {

    @Test public void test() {
        due("sha3", this::sha3);
//        due("sha256", this::sha256);
//        due("twiceSha256", this::twiceSha256);
        due("guavaSha256", this::guavaSha256);
        due("guavaTwiceSha256", this::guavaTwiceSha256);
        due("md5", this::md5);
        due("murmur3_32", this::murmur3_32);
        due("murmur3_128", this::murmur3_128);
    }

    public void due(String name, Function<String, String> f) {
        long startTime = System.currentTimeMillis();
        for (int i = 0; i < 5; i++) {
            String tx ="75d6ecc9f2880d87e22c39cc01fe9be7cc8a6612b73d4052b0262cf7a910a329";
            String s = f.apply(tx);
                System.out.println("s = " + s);
        }
        System.out.println(name + " due = " + (System.currentTimeMillis() - startTime));
    }

    private String sha3(String value) {
        byte[] bytes = HashUtil.sha3(value.getBytes(Charsets.UTF_8));
        return Hex.toHexString(bytes);
    }

//    private String sha256(String value) {
//        byte[] bytes = HashUtil.sha256(value);
//        return Hex.toHexString(bytes);
//    }
//
//    private String twiceSha256(String value) {
//        byte[] bytes = HashUtil.twiceSha256(value);
//        return Hex.toHexString(bytes);
//    }

    private String guavaSha256(String value) {
        HashCode code = Hashing.sha256().hashString(value, Charsets.UTF_8);
        return code.toString();
    }

    private String guavaTwiceSha256(String value) {
        HashCode code = Hashing.sha256().hashString(value, Charsets.UTF_8);
        code = Hashing.sha256().hashBytes(code.asBytes());
        return code.toString();
    }

    private String md5(String value) {
        HashFunction md5 = Hashing.md5();
        HashCode code = md5.hashString(value, Charsets.UTF_8);
        return code.toString();
    }

    private String murmur3_32(String value) {
        HashFunction md5 = Hashing.murmur3_32(4);
        HashCode code = md5.hashString(value, Charsets.UTF_8);
        return code.toString();
    }

    private String murmur3_128(String value) {
        HashFunction md5 = Hashing.murmur3_128(4);
        HashCode code = md5.hashString(value, Charsets.UTF_8);
        return code.toString();
    }






}
