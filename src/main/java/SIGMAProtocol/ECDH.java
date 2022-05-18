package SIGMAProtocol;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.*;

public class ECDH {

    private static KeyPairGenerator kpg;
    @Getter
    @Setter
    private static int keySize = 256;

    public ECDH(){
        try {
            kpg = KeyPairGenerator.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair getKeyPair(){
        kpg.initialize(keySize);
        return kpg.generateKeyPair();
    }

    public static SecretKey GetSecret(PrivateKey secretKeyX, PublicKey publicKeyY){
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(secretKeyX);
            keyAgreement.doPhase(publicKeyY,true);
            SecretKey sharedSecret = keyAgreement.generateSecret("AES");
            return sharedSecret;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } finally {
            return null;
        }
    }
}