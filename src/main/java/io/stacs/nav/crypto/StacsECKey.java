/*
 * Copyright (c) 2013-2017, suimi
 */
package io.stacs.nav.crypto;

import com.google.common.base.Charsets;
import io.stacs.nav.crypto.utils.HashUtil;
import lombok.extern.slf4j.Slf4j;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SignatureException;

/**
 * @author suimi
 * @date 2018/12/12
 */
@Slf4j public class StacsECKey extends ECKey {

    public StacsECKey() {
    }

    public StacsECKey(Provider provider, SecureRandom secureRandom) {
        super(provider, secureRandom);
    }

    public StacsECKey(SecureRandom secureRandom) {
        super(secureRandom);
    }

    public StacsECKey(Provider provider, PrivateKey privKey, ECPoint pub) {
        super(provider, privKey, pub);
    }

    public StacsECKey(BigInteger priv, ECPoint pub) {
        super(priv, pub);
    }

    /**
     * Creates an ECKey given the private key only.
     *
     * @param privKey -
     * @return -
     */
    public static StacsECKey fromPrivate(BigInteger privKey) {
        return new StacsECKey(privKey, CURVE.getG().multiply(privKey));
    }

    /**
     * Creates an ECKey given the private key only.
     *
     * @param privKeyBytes -
     * @return -
     */
    public static StacsECKey fromPrivate(byte[] privKeyBytes) {
        return fromPrivate(new BigInteger(1, privKeyBytes));
    }

    /**
     * Creates an ECKey that cannot be used for signing, only verifying signatures, from the given point. The
     * compression state of pub will be preserved.
     *
     * @param pub -
     * @return -
     */
    public static StacsECKey fromPublicOnly(ECPoint pub) {
        return new StacsECKey(null, pub);
    }

    /**
     * Creates an ECKey that cannot be used for signing, only verifying signatures, from the given encoded point.
     * The compression state of pub will be preserved.
     *
     * @param pub -
     * @return -
     */
    public static StacsECKey fromPublicOnly(byte[] pub) {
        return new StacsECKey(null, CURVE.getCurve().decodePoint(pub));
    }

    /**
     * Compute the key that signed the given signature.
     *
     * @param message   message
     * @param signature Hex encoded signature
     * @return ECKey
     */
    public static StacsECKey signedMessageToKey(String message, String signature) throws SignatureException {
        byte[] messageHash = HashUtil.sha256(message.getBytes(Charsets.UTF_8));
        byte[] signatureEncoded = Hex.decode(signature);
        final byte[] keyBytes = signatureToKeyBytes(messageHash, signatureEncoded);
        return fromPublicOnly(keyBytes);
    }

    /**
     * Compute the key that signed the given signature.
     *
     * @param message   message
     * @param signature Hex encoded signature
     * @return ECKey
     */
    public static StacsECKey signedMessageToKey(byte[] message, String signature) throws SignatureException {
        byte[] messageHash = HashUtil.sha256(message);
        byte[] signatureEncoded = Hex.decode(signature);
        final byte[] keyBytes = signatureToKeyBytes(messageHash, signatureEncoded);
        return fromPublicOnly(keyBytes);
    }

    /**
     * Given a piece of text and a message signature encoded in base64, returns an ECKey
     * containing the public key that was used to sign it. This can then be compared to the expected public key to
     * determine if the signature was correct.
     *
     * @param messageHash      a piece of human readable text that was signed
     * @param signatureEncoded The Ethereum-format message signature in byte
     * @return -
     * @throws SignatureException If the public key could not be recovered or if there was a signature format error.
     */
    public static byte[] signatureToKeyBytes(byte[] messageHash, byte[] signatureEncoded) throws SignatureException {
        // Parse the signature bytes into r/s and the selector value.
        if (signatureEncoded.length < 65)
            throw new SignatureException("Signature truncated, expected 65 bytes and got " + signatureEncoded.length);

        return signatureToKeyBytes(messageHash, ECDSASignature.decodeFromSignature(signatureEncoded));
    }

    /**
     * Compute the key that signed the given signature.
     *
     * @param messageHash 32-byte hash of message
     * @param sig         -
     * @return ECKey
     */
    public static StacsECKey signatureToKey(byte[] messageHash, ECDSASignature sig) throws SignatureException {
        final byte[] keyBytes = signatureToKeyBytes(messageHash, sig);
        return fromPublicOnly(keyBytes);
    }

    /**
     * @param message   the message
     * @param signature Hex encoded signature
     * @param owner     Hex encoded public key or address
     * @return
     */
    public static boolean verify(String message, String signature, String owner) {
        byte[] messageHash = HashUtil.sha256(message.getBytes(Charsets.UTF_8));
        byte[] signatureEncoded = Hex.decode(signature);
        ECDSASignature ecdsaSignature = ECDSASignature.decodeFromSignature(signatureEncoded);
        byte[] pubKey;
        try {
            if (owner.length() == 40) {
                byte[] bytes = signatureToAddress(messageHash, ecdsaSignature);
                if (!owner.equalsIgnoreCase(Hex.toHexString(bytes))) {
                    return false;
                }
                pubKey = signatureToKeyBytes(messageHash, ecdsaSignature);
            } else {
                pubKey = Hex.decode(owner);
            }
        } catch (SignatureException e) {
            log.warn("verify sign error", e);
            return false;
        }
        return verify(messageHash, ecdsaSignature, pubKey);
    }

    /**
     * compute the address with given public key
     *
     * @param pubkey Hex encoded public key
     * @return hex encoded address
     */
    public static String pubkey2Address(String pubkey) {
        return Hex.toHexString(fromPublicOnly(Hex.decode(pubkey)).getAddress());
    }

    /**
     * compute the address with given signature
     *
     * @param message
     * @param signature
     * @return
     * @throws SignatureException
     */
    public static String signatureToAddress(String message, String signature) throws SignatureException {
        byte[] messageHash = HashUtil.sha256(message.getBytes(Charsets.UTF_8));
        byte[] signatureEncoded = Hex.decode(signature);
        return Hex.toHexString(computeAddress(signatureToKeyBytes(messageHash, signatureEncoded)));
    }

    /**
     * compute the address with given signature
     *
     * @param message
     * @param signature
     * @return
     * @throws SignatureException
     */
    public static String signatureToAddress(byte[] message, String signature) throws SignatureException {
        byte[] messageHash = HashUtil.sha256(message);
        byte[] signatureEncoded = Hex.decode(signature);
        return Hex.toHexString(computeAddress(signatureToKeyBytes(messageHash, signatureEncoded)));
    }

    /**
     * get the hex encoded address
     */
    public String getHexAddress() {
        return Hex.toHexString(getAddress());
    }

    public static boolean checkAddress(String addr) {
        try {
            return Hex.decode(addr).length == 20;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * get the hex encoded public key
     *
     * @return
     */
    public String getPublicKeyAsHex() {
        return Hex.toHexString(getPubKey());
    }

    /**
     * sign the message
     *
     * @param message the message
     * @return hex encoded sign value
     */
    public String signMessage(String message) {
        byte[] bytes = HashUtil.sha256(message.getBytes(Charsets.UTF_8));
        return sign(bytes).toHex();
    }

    /**
     * sign the message
     *
     * @param message the message
     * @return hex encoded sign value
     */
    public String signMessage(byte[] message) {
        byte[] bytes = HashUtil.sha256(message);
        return sign(bytes).toHex();
    }

    /**
     * use private key sign
     *
     * @param priKey  private key
     * @param message message
     * @return signature of hexString
     */
    public static String signMsgForContract(String priKey, String message) {
        return fromPrivate(Hex.decode(priKey)).sign(Hex.decode(message)).toHex();
    }

    /**
     * use current private key sign
     *
     * @param message message
     * @return signature of hexString
     */
    public String signMsgForContract(String message) {
        return sign(Hex.decode(message)).toHex();
    }

    /**
     * verify address matches with public key
     */
    public static boolean verifyPubkeyAndAddr(String address, String publicKey) {
        return pubkey2Address(publicKey).equalsIgnoreCase(address);
    }

}
