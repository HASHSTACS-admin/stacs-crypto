package io.stacs.nav.crypto;

import io.stacs.nav.crypto.jce.ECKeyAgreement;
import io.stacs.nav.crypto.jce.ECKeyPointAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;

/**
 * @author suimi
 * @date 2019/11/7
 */
public class ECKeyTest {

    @Test public void test() {
        ECKey ecKey = new ECKey();
        String priKey = ecKey.getPrivKey().toString(16);
        System.out.println("ecKey = " + priKey);
        System.out.println("ecKey = " + Hex.toHexString(ecKey.getPrivKeyBytes()));
        System.out.println("ecKey = " + Hex.toHexString(ecKey.getPubKey()));

        ECKey ecKey1 = ecKey.fromPrivate(Hex.decode(priKey));
        System.out.println("ecKey1 = " + ecKey.getPrivKey().toString(16));
        System.out.println("ecKey1 = " + Hex.toHexString(ecKey1.getPubKey()));
    }

    @Test public void test1() {
        ECKey ecKey = new ECKey();
        String priKey = ecKey.getPrivKey().toString(16);
        System.out.println("ecKey = " + priKey);
        PrivateKey privateKey = ECKey.privateKeyFromBytes(ecKey.getPrivKeyBytes());
        byte[] bytes = ECKey.priKey2Bytes(privateKey);
        System.out.println("privateKey = " + Hex.toHexString(bytes));

        System.out.println("ecKey = " + Hex.toHexString(ecKey.getPubKey()));
        PublicKey publicKey = ECKey.publicKeyFromBytes(ecKey.getPubKey());
        System.out.println("publicKey = " + Hex.toHexString(ECKey.pubKey2Bytes(publicKey)));
    }

    @Test public void test2ECDH() throws InvalidKeyException {

        ECKey a = new ECKey();
        ECKey b = new ECKey();

        PrivateKey aPriKey = ECKey.privateKeyFromBigInteger(a.getPrivKey());
        PublicKey aPubKey = ECKey.publicKeyFromBytes(a.getPubKey());

        PrivateKey bPriKey = ECKey.privateKeyFromBigInteger(b.getPrivKey());
        PublicKey bPubKey = ECKey.publicKeyFromBytes(b.getPubKey());

        KeyAgreement agreement = ECKeyAgreement.getInstance();
        agreement.init(aPriKey);
        agreement.doPhase(bPubKey, true);
        System.out.println("a: " + Hex.toHexString(agreement.generateSecret()));

        KeyAgreement bAgreement = ECKeyAgreement.getInstance();
        bAgreement.init(bPriKey);
        bAgreement.doPhase(aPubKey, true);
        System.out.println("b: " + Hex.toHexString(bAgreement.generateSecret()));

    }

    @Test public void test2ECDHBC() throws InvalidKeyException {

        ECKey a = new ECKey();
        ECKey b = new ECKey();

        PrivateKey aPriKey = ECKey.privateKeyFromBigInteger(a.getPrivKey());
        PublicKey aPubKey = ECKey.publicKeyFromBytes(a.getPubKey());

        PrivateKey bPriKey = ECKey.privateKeyFromBigInteger(b.getPrivKey());
        PublicKey bPubKey = ECKey.publicKeyFromBytes(b.getPubKey());

        KeyAgreement agreement = ECKeyAgreement.getInstance();
        agreement.init(aPriKey);
        agreement.doPhase(bPubKey, true);
        System.out.println("a: " + Hex.toHexString(agreement.generateSecret()));

        KeyAgreement bAgreement = ECKeyAgreement.getInstance();
        bAgreement.init(bPriKey);
        bAgreement.doPhase(aPubKey, true);
        System.out.println("b: " + Hex.toHexString(bAgreement.generateSecret()));

        ECDHBasicAgreement ecdhBasicAgreement = new ECDHBasicAgreement();
        CipherParameters cipherParameters = new ECPrivateKeyParameters(a.getPrivKey(), ECKey.CURVE);
        ecdhBasicAgreement.init(cipherParameters);
        ECPublicKeyParameters pubKeyParam = new ECPublicKeyParameters(b.getPubKeyPoint(), ECKey.CURVE);
        BigInteger bigInteger = ecdhBasicAgreement.calculateAgreement(pubKeyParam);
        System.out.println("a: " + bigInteger.toString(16));

    }



    @Test public void test3ECDHP() throws InvalidKeyException {

        ECKey a = new ECKey();
        ECKey b = new ECKey();
        ECKey c = new ECKey();
        ECKey d = new ECKey();


        print(calculate(a, b));
        print(calculate(b, a));
        System.out.println();
        print(calculate(a, b, c));
        print(calculate(a, c, b));
        print(calculate(b, a, c));
        print(calculate(b, c, a));
        print(calculate(c, a, b));
        print(calculate(c, b, a));
        System.out.println();

        print(calculate(d, a, b, c));
        print(calculate(d, b, a, c));
        print(calculate(d, b, c, a));
        print(calculate(d, b, a, c));
        print(calculate(d, c, a, b));
        print(calculate(d, c, b, a));

        print(calculate(a, d, b, c));
        print(calculate(b, d, a, c));
        print(calculate(b, d, c, a));
        print(calculate(b, d, a, c));
        print(calculate(c, d, a, b));
        print(calculate(c, d, b, a));

        print(calculate(a, b, d, c));
        print(calculate(b, a, d, c));
        print(calculate(b, c, d, a));
        print(calculate(b, a, d, c));
        print(calculate(c, a, d, b));
        print(calculate(c, b, d, a));

        print(calculate(a, b, c, d));
        print(calculate(b, a, c, d));
        print(calculate(b, c, a, d));
        print(calculate(b, a, c, d));
        print(calculate(c, a, b, d));
        print(calculate(c, b, a, d));
        System.out.println();
    }

    private void print(ECPoint point) {
        System.out.println("value = " + point.getAffineXCoord().toBigInteger().toString(16));
    }

    public ECPoint calculate(ECKey a, ECKey b) {
        ECKeyPointAgreement aAgreement = new ECKeyPointAgreement();
        CipherParameters apriKeyParam = new ECPrivateKeyParameters(a.getPrivKey(), ECKey.CURVE);
        aAgreement.init(apriKeyParam);
        return aAgreement.calculateAgreement(b.getPubKeyPoint());
    }

    public ECPoint calculate(ECKey a, ECKey b, ECKey c) {
        ECKeyPointAgreement cAgreement = new ECKeyPointAgreement();
        CipherParameters cpriKeyParam = new ECPrivateKeyParameters(c.getPrivKey(), ECKey.CURVE);
        cAgreement.init(cpriKeyParam);
        return cAgreement.calculateAgreement(calculate(a, b));
    }

    public ECPoint calculate(ECKey a, ECKey b, ECKey c, ECKey d) {
        ECKeyPointAgreement dAgreement = new ECKeyPointAgreement();
        CipherParameters dpriKeyParam = new ECPrivateKeyParameters(d.getPrivKey(), ECKey.CURVE);
        dAgreement.init(dpriKeyParam);

        return dAgreement.calculateAgreement(calculate(a, b, c));
    }

    @Test public void test3ECDH() throws InvalidKeyException, NoSuchAlgorithmException {

        ECKey a = new ECKey();
        ECKey b = new ECKey();
        ECKey c = new ECKey();

        PrivateKey aPriKey = ECKey.privateKeyFromBigInteger(a.getPrivKey());
        PublicKey aPubKey = ECKey.publicKeyFromBytes(a.getPubKey());

        PrivateKey bPriKey = ECKey.privateKeyFromBigInteger(b.getPrivKey());
        PublicKey bPubKey = ECKey.publicKeyFromBytes(b.getPubKey());

        PrivateKey cPriKey = ECKey.privateKeyFromBigInteger(c.getPrivKey());
        PublicKey cPubKey = ECKey.publicKeyFromBytes(c.getPubKey());

        //        secret(aPriKey, bPubKey, cPubKey);
        //        secret(bPriKey, aPubKey, cPubKey);
        //        secret(cPriKey, aPubKey, bPubKey);

        KeyAgreement agreement = ECKeyAgreement.getInstance();
        agreement.init(aPriKey);
        agreement.doPhase(bPubKey, false);
        agreement.doPhase(cPubKey, true);
        System.out.println("a: " + Hex.toHexString(agreement.generateSecret()));

        KeyAgreement bAgreement = ECKeyAgreement.getInstance();
        bAgreement.init(bPriKey);
        bAgreement.doPhase(aPubKey, false);
        bAgreement.doPhase(cPubKey, true);
        System.out.println("b: " + Hex.toHexString(bAgreement.generateSecret()));

        KeyAgreement cAgreement = ECKeyAgreement.getInstance();
        cAgreement.init(cPriKey);
        cAgreement.doPhase(bPubKey, false);
        cAgreement.doPhase(aPubKey, true);
        System.out.println("c: " + Hex.toHexString(cAgreement.generateSecret()));
    }

    private void secret(PrivateKey privateKey, PublicKey... publicKeys)
        throws InvalidKeyException, NoSuchAlgorithmException {

        KeyAgreement agreement = ECKeyAgreement.getInstance();
        agreement.init(privateKey);
        agreement.doPhase(publicKeys[0], true);
        System.out.println("a: " + Hex.toHexString(agreement.generateSecret()));

        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(agreement.generateSecret());
        for (PublicKey publicKey : publicKeys) {
            hash.update(ECKey.pubKey2Bytes(publicKey));
        }
        byte[] derivedKey = hash.digest();
        System.out.println("derivedKey = " + Hex.toHexString(derivedKey));
    }

}
