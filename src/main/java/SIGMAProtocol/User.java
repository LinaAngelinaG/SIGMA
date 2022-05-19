package SIGMAProtocol;

import SIGMAProtocol.HMAC.HMAC;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

@Getter(AccessLevel.PACKAGE)
public class User {
    private KeyPair keyPair;
    @Getter
    @Setter(AccessLevel.PACKAGE)
    private PublicKey publicKeyAnother;
    private byte[] rA = null;
    private byte[] rB = null;
    private byte[] key_m = null;
    private byte[] key_e = null;

    private HMAC hmac;
    private Cipher cipher;
    private ECDSA ecdsa;
    @Setter
    @Getter
    private static int sizeOfArr = 8;
    private int sizeOfResponse;

    public User(){
        try {
            hmac = new HMAC();
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            ecdsa = new ECDSA();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public void shareWith(User user){
        this.publicKeyAnother = user.getPublicKeyAnother();
        user.publicKeyAnother = publicKeyAnother;
    }
    protected String startSession(){
        ECDH ecdh = new ECDH();
        keyPair = ecdh.getKeyPair();
        ecdsa.init(keyPair);
        rA = generateByteArray();
        return getB(rA);
    }
    protected String giveResponse(String message){
        ECDH ecdh = new ECDH();
        gain_rA(message);
        keyPair = ecdh.getKeyPair();
        try {
            rB = generateByteArray();
            calculateKeys();
            ecdsa.init(keyPair);
            hmac.setKey(key_m);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key_e,0, key_e.length, "AES"));
            byte[] response = cipher.doFinal(getA(message));
            sizeOfResponse = response.length;
            return Arrays.toString(response);
        } catch (NoSuchAlgorithmException |
                 IOException |
                 InvalidKeyException |
                 IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private void calculateKeys(){
        try {
            byte[] secret = ECDH.GetSecret(keyPair.getPrivate(),
                    publicKeyAnother).getEncoded();
            hmac.setKey(concatenate(rA,rB));
            secret = hmac.ComputeMac(secret);
            key_m = Arrays.copyOfRange(secret,0,sizeOfArr);
            key_e = Arrays.copyOfRange(secret,sizeOfArr,secret.length);
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    protected String finaliseConnection(String message) throws RuntimeException {
        try {
            calculateKeys();
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key_e,0, key_e.length, "AES"));
            byte[] decrypred = cipher.doFinal(message.getBytes());
            gain_rB(decrypred);
            if(!verification(decrypred)){
                throw new RuntimeException("Verification of signature in gained message is failed");
            };
            return getFinalAnswer(message);
        } catch (InvalidKeyException |
                 IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    protected boolean doFinalVerificationWithProtocol(String message) throws RuntimeException {
        try {
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key_e,0, key_e.length, "AES"));
            byte[] decrypred = cipher.doFinal(message.getBytes());
            int len = decrypred.length - hmac.getByteBlockSize();
            byte[] ver1 = Arrays.copyOfRange(decrypred,0,sizeOfResponse);
            byte[] macVer = Arrays.copyOfRange(decrypred,
                    decrypred.length-sizeOfArr*2, decrypred.length);
            if(!Arrays.equals(hmac.ComputeMac(ver1),macVer)){
                throw new RuntimeException("Authentication failed");
            }
            byte[] signature = Arrays.copyOfRange(decrypred,sizeOfResponse,len);
            return ecdsa.VERIFY(concat(),signature);
        } catch (InvalidKeyException |
                 BadPaddingException |
                 IllegalBlockSizeException |
                 NoSuchAlgorithmException |
                 IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String getFinalAnswer(String message){
        try {
            byte[] concat = concatenate(publicKeyAnother.getEncoded(),
                    keyPair.getPrivate().getEncoded());
            return Arrays.toString(
                    concatenate(
                            concatenate(
                                    concatenate(
                                            message.getBytes(),
                                            ecdsa.SIGN(concat).getBytes()),
                                    ecdsa.SIGN(concat).getBytes()),
                            hmac.ComputeMac(message.getBytes()) ));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void gain_rA(String mes){
        byte[] m = mes.getBytes();
        rA = Arrays.copyOfRange(m, publicKeyAnother.getEncoded().length, m.length);
    }

    private void gain_rB(byte[] mes){
        int len = publicKeyAnother.getEncoded().length;
        rA = Arrays.copyOfRange(mes, len, len + sizeOfArr);
    }

    private static byte[] generateByteArray(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] result = new byte[sizeOfArr];
        secureRandom.nextBytes(result);
        return result;
    }
    private String getB(byte[] arr2){
        byte[] arr1 = keyPair.getPublic().getEncoded();
        return Arrays.toString(concatenate(arr1,arr2));
    }
    private byte[] getA(String s) throws NoSuchAlgorithmException, IOException {
        byte[] concat = concatenate(publicKeyAnother.getEncoded(),keyPair.getPrivate().getEncoded());
        return concatenate(
                concatenate(
                        concatenate(
                                concatenate(
                                        keyPair.getPublic().getEncoded(),
                                        rB),
                                s.getBytes()),
                        ecdsa.SIGN(concat).getBytes()),
                hmac.ComputeMac(s.getBytes()) );
    }

    private boolean verification(byte[] message){
        try {
            int len = publicKeyAnother.getEncoded().length;
            int len1 = len + sizeOfArr;
            byte[] ver1 = Arrays.copyOfRange(message,len1,len1+len+sizeOfArr);
            byte[] macVer = Arrays.copyOfRange(message,
                    message.length-sizeOfArr*2, message.length);
            if(!Arrays.equals(hmac.ComputeMac(ver1),macVer)){
                throw new RuntimeException("Authentication failed");
            }
            byte[] sign = Arrays.copyOfRange(message,
                    rB.length+len,
                    message.length-hmac.getByteBlockSize());
            return ecdsa.VERIFY(concat(),sign);
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }
    private byte[] concat(){
        return concatenate(publicKeyAnother.getEncoded(),keyPair.getPublic().getEncoded());
    }

    private byte[] concatenate(byte[] arr1, byte[] arr2){
        byte[] result = new byte[arr1.length*2];
        for(int i=0;i<result.length;++i){
            result[i] = i < result.length/2? arr1[i] : arr2[i];
        }
        return result;
    }
}
