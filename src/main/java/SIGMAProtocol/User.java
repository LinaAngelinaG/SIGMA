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
            calculateKey_m();
            calculateKey_e();
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

    private void calculateKey_e(){
        key_e = ECDH.GetSecret(keyPair.getPrivate(),
                publicKeyAnother).getEncoded();
    }

    private void calculateKey_m(){
        try {
            hmac.MacAddBlock(rA);
            hmac.MacAddBlock(rB);
            key_m = hmac.MacFinalize();
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    protected String finaliseConnection(String message) throws RuntimeException {
        try {
            calculateKey_e();
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key_e,0, key_e.length, "AES"));
            byte[] decrypred = cipher.doFinal(message.getBytes());
            gain_rB(decrypred);
            calculateKey_m();
            if(!verification(decrypred)){
                System.out.println("Verification of signature in gained message is failed");
            };
            return getFinalAnswer(message);
        } catch (InvalidKeyException |
                 IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    protected boolean doFinalVerificationWithProtocol(String message){
        try {
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key_e,0, key_e.length, "AES"));
            byte[] decrypred = cipher.doFinal(message.getBytes());
            int len = decrypred.length - hmac.getByteBlockSize();
            byte[] signature = Arrays.copyOfRange(decrypred,sizeOfResponse,len);
            return ecdsa.VERIFY(concat(),signature);
        } catch (InvalidKeyException |
                 BadPaddingException |
                 IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }
    }

    private String getFinalAnswer(String message){
        try {
            StringBuilder builder = new StringBuilder();
            StringBuilder builder1 = new StringBuilder();
            builder1.append(publicKeyAnother).append(keyPair.getPublic());
            builder
                    .append(message)
                    .append(ecdsa.SIGN(builder1
                            .toString()
                            .getBytes() ) )
                    .append(hmac.ComputeMac(message.getBytes()));
            return builder.toString();
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
    private String getB(byte[] arr){
        StringBuilder builder = new StringBuilder();
        builder.append(keyPair.getPublic())
                .append(arr);
        return builder.toString();
    }
    private byte[] getA(String s) throws NoSuchAlgorithmException, IOException {
        StringBuilder builder = new StringBuilder();
        StringBuilder builder1 = new StringBuilder();
        builder1.append(publicKeyAnother).append(keyPair.getPrivate());
        builder
                .append(keyPair.getPublic())
                .append(rB)
                .append(s)
                .append(ecdsa.SIGN(builder1
                        .toString()
                        .getBytes()) )
                .append(hmac.ComputeMac(s.getBytes()) );
        return builder.toString().getBytes();
    }

    private boolean verification(byte[] message){
        int len = publicKeyAnother.getEncoded().length;
        byte[] sign = Arrays.copyOfRange(message,
                rB.length+len,
                message.length-hmac.getByteBlockSize());
        return ecdsa.VERIFY(concat(),sign);
    }
    private byte[] concat(){
        StringBuilder stringBuilder = new StringBuilder();
        return stringBuilder
                .append(publicKeyAnother)
                .append(keyPair.getPublic())
                .toString()
                .getBytes();
    }
}
