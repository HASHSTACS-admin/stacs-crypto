package io.stacs.nav.crypto;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import java.security.SignatureException;

import static org.junit.Assert.assertTrue;

/**
 * @author dekuofa <br>
 * @date 2019-11-08 <br>
 */
@Slf4j public class StacsECKeyTest {
    private String privateKey = "78637c920bc993f50c038fa146b917fc625793e59f677cdbfbbe1c46b7fd407a";
    private String publicKey =
        "04eb1a1d24b2456b600b5ba594f9783a6d51bec678ef57cdb5c7127d107a956c0240e89d41bfe164e8ef7a21f43f4c16e6a46874d9835929422b3264602186c79c";

    @Test public void signTest() throws SignatureException {
        String message = "1f8cf317-ef14-42be-90cc-d5547084b519ContractBD_BCONTRACT_ISSUEnullnull54bd202186dd2de178ea220a875136a9dea736ce18a93960ed0ad0ee6cc4206abcfa90cc76befa9eBnullCREATE_CONTRACT";
        StacsECKey ecKey = StacsECKey.fromPrivate(Hex.decode(privateKey));
        String signMessage = ecKey.signMessage(message);
        System.out.println("signMessage = " + signMessage);
        System.out.println(StacsECKey.signatureToAddress(message, signMessage));
        System.out.println(StacsECKey.signedMessageToKey(message, signMessage));
        System.out.println(StacsECKey.verify(message, signMessage, ecKey.getHexAddress()));
        assertTrue(StacsECKey.verify(message, signMessage, ecKey.getHexAddress()));

    }

    @Test public void test() throws SignatureException {
        for (int i = 0; i < 1; i++) {
            StacsECKey key = new StacsECKey();
            String pubkey = Hex.toHexString(key.getPubKey());
            String privkey = Hex.toHexString(key.getPrivKeyBytes());
            String addr = key.getHexAddress();
            String message = "lingchao";
            System.out.println("pubkey：" + pubkey + " size:" + key.getPubKey().length);
            System.out.println("prikey:" + privkey + " size:" + key.getPrivKeyBytes().length);
            System.out.println("addr:" + addr + " size:" + key.getAddress().length);
            System.out.println("pubkey to addr is equal :" + StacsECKey.pubkey2Address(pubkey).equalsIgnoreCase(addr));

            System.out.println("checkAddress: " + StacsECKey.checkAddress(addr));
            StacsECKey ecKey = StacsECKey.fromPrivate(Hex.decode(privkey));
            String signature = ecKey.signMessage(message);

            System.out.println(
                pubkey.equalsIgnoreCase(StacsECKey.signedMessageToKey(message, signature).getPublicKeyAsHex()));
            System.out.println("signature  :" + StacsECKey
                .verify(message, signature, StacsECKey.signedMessageToKey(message, signature).getPublicKeyAsHex()));
            System.out.println("signature  :" + StacsECKey.verify(message + 1, signature, addr));
            System.out.println(
                "sign to addr is equal :" + StacsECKey.signatureToAddress(message, signature).equalsIgnoreCase(addr));
        }
    }
}
