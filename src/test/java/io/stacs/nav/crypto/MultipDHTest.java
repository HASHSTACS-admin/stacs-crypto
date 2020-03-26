package io.stacs.nav.crypto;

import io.stacs.nav.crypto.jce.ECKeyPointAgreement;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author suimi
 * @date 2019/11/20
 */
public class MultipDHTest {

    @Setter @Getter @AllArgsConstructor static class NodeKey {
        private String name;
        private ECKey ecKey;

    }

    @Setter @Getter @AllArgsConstructor static class NodePubKey {
        private String name;
        private String pubKey;

    }

    @Getter @Setter @AllArgsConstructor static class GECpoint {
        private String name;
        private ECPoint point;

        @Override public String toString() {
            return String.format("%10s : %s", name, point.getAffineXCoord().toBigInteger().toString(16));
        }
    }

    public GECpoint calculate(NodeKey nk, NodePubKey npk) {
        ECKeyPointAgreement dAgreement = new ECKeyPointAgreement();
        CipherParameters dpriKeyParam = new ECPrivateKeyParameters(nk.getEcKey().getPrivKey(), ECKey.CURVE);
        dAgreement.init(dpriKeyParam);
        ECKey npkey = ECKey.fromPublicOnly(Hex.decode(npk.getPubKey()));
        ECPoint ecPoint = dAgreement.calculateAgreement(npkey.getPubKeyPoint());
        GECpoint newPoint = new GECpoint(nk.getName() + "_" + npk.getName(), ecPoint);
        System.out.println(newPoint);
        return newPoint;
    }

    public GECpoint calculate(NodeKey nk, GECpoint geCpoint) {
        ECKeyPointAgreement dAgreement = new ECKeyPointAgreement();
        CipherParameters dpriKeyParam = new ECPrivateKeyParameters(nk.getEcKey().getPrivKey(), ECKey.CURVE);
        dAgreement.init(dpriKeyParam);
        ECPoint ecPoint = dAgreement.calculateAgreement(geCpoint.getPoint());
        GECpoint newPoint = new GECpoint(nk.getName() + "_" + geCpoint.getName(), ecPoint);
        System.out.println(newPoint);
        return newPoint;
    }

    @Test public void test() {
        int size = 4;
        ArrayList<NodeKey> nodeKeys = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            nodeKeys.add(new NodeKey("N" + i, new ECKey()));
        }

        List<NodePubKey> pubKeys = new ArrayList<>();
        Map<Integer, List<GECpoint>> pointMap = new ConcurrentHashMap<>();

        for (int i = 0; i < size; i++) {
            System.out.println(" = = = = = = = = = = = = " + i);
            NodeKey key = nodeKeys.get(i);
            for (int j = i; j >= 2; j--) {
                List<GECpoint> existPoint = pointMap.getOrDefault(j, new ArrayList<>());
                List<GECpoint> newPoint = pointMap.getOrDefault(j + 1, new ArrayList<>());
                for (GECpoint geCpoint : existPoint) {
                    newPoint.add(calculate(key, geCpoint));
                }
                pointMap.put(j + 1, newPoint);
                System.out.println(" = = = " + j);
            }

            List<GECpoint> twoPoint = pointMap.getOrDefault(2, new ArrayList<>());
            for (NodePubKey pubKey : pubKeys) {
                twoPoint.add(calculate(key, pubKey));
            }
            pointMap.put(2, twoPoint);
            pubKeys.add(new NodePubKey(key.getName(), key.getEcKey().getHexPubKey()));
        }
        System.out.println(" = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = ");

        for (GECpoint geCpoint : pointMap.get(size - 1 < 2 ? 2 : size - 1)) {
            System.out.println(geCpoint);
        }

        System.out.println(" = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = ");
        List<GECpoint> geCpoints = pointMap.get(size - 1 < 2 ? 2 : size - 1);
        for (int i = 0; i < size - 1; i++) {
            NodeKey key = nodeKeys.get(i);
            if (size == 2) {
                NodePubKey nodePubKey = pubKeys.get(size - 1);
                calculate(key, nodePubKey);
                break;
            }
            String name = key.getName();
            for (GECpoint geCpoint : geCpoints) {
                long count = Arrays.stream(geCpoint.getName().split("_")).filter(s -> s.equalsIgnoreCase(name)).count();
                if (count == 0) {
                    calculate(key, geCpoint);
                    break;
                }
            }
        }
    }
}
