package io.stacs.nav.crypto.jce;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * @author suimi
 * @date 2019/11/8
 */
public class ECKeyPointAgreement {
    private ECPrivateKeyParameters key;

    public void init(CipherParameters key) {
        this.key = (ECPrivateKeyParameters)key;
    }

    public int getFieldSize() {
        return (key.getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public ECPoint calculateAgreement(ECPoint point) {
        ECPoint P = point.multiply(key.getD()).normalize();
        if (P.isInfinity()) {
            throw new IllegalStateException("Infinity is not a valid agreement value for ECDH");
        }
        return P;
    }

}