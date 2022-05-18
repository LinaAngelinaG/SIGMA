package SIGMAProtocol;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.math.BigInteger;
import java.security.*;

public class ECDSA {
    private static Signature ecdsa;
    private static KeyPair keyPair = null;

    public ECDSA(){
        try {
            ecdsa = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void init(KeyPair pair){
        keyPair = pair;
    }
    public String SIGN(byte[] message){
        try {
            checkKeyPair();
            ecdsa.initSign(keyPair.getPrivate());
            ecdsa.update(message);
            byte[] realSig = ecdsa.sign();
            keyPair = null;
            return new BigInteger(1, realSig).toString(16);
        } catch (SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean VERIFY(byte[] message, byte[] signature){
        try {
            ecdsa.initVerify(keyPair.getPublic());
            ecdsa.update(message);
            keyPair = null;
            return ecdsa.verify(signature);
        } catch (SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static void checkKeyPair(){
        if(keyPair == null){
            throw new RuntimeException("KeyPair is not initialized");
        }
    }
}
