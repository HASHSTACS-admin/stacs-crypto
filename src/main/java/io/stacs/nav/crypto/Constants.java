package io.stacs.nav.crypto;

import java.math.BigInteger;

public class Constants {
    private static final BigInteger SECP256K1N =
        new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);

    /**
     * Introduced in the Homestead release
     *
     * @return the secp 256 k 1 n
     */
    public static BigInteger getSECP256K1N() {
        return SECP256K1N;
    }
}
