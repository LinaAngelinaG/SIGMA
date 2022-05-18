package SIGMAProtocol.HMAC;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HMAC {
    private MessageDigest digest = MessageDigest.getInstance("SHA-256");
    private byte[] previousBlock = null;
    private byte[] currentTag = null;
    private byte[] key = null;
    private byte[] keyOne = null;
    private byte[] keyTwo = null;
    private int byteBlockSize = 16;

    public int getByteBlockSize() {
        return byteBlockSize;
    }
    public void setByteBlockSize(int size) { byteBlockSize = size;}
    public boolean isEmpty(){ return previousBlock == null;}

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) throws NoSuchAlgorithmException {
        this.key = key != null ? key : KeyGenerating.generateKey().getEncoded();
        byteBlockSize = key.length;
        reset();
    }

    private void reset(){
        countKeys();
        digest.reset();
        digest.update(keyOne);
    }

    public HMAC(byte[] key) throws NoSuchAlgorithmException {
        setKey(key);
    }

    public HMAC() throws NoSuchAlgorithmException {
        setKey(KeyGenerating.generateKey().getEncoded());
    }

    public void MacAddBlock(byte[] dataBlock) throws IOException, NoSuchAlgorithmException {
        if(previousBlock != null){
            digest.update(previousBlock);
        }
        previousBlock = dataBlock;
    }

    public byte[] MacFinalize() throws NoSuchAlgorithmException, IOException {
        digest.update(previousBlock);
        previousBlock = digest.digest();
        digest.update(keyTwo);
        digest.update(previousBlock);
        currentTag = digest.digest();
        previousBlock = null;
        return currentTag;
    }

    public byte[] ComputeMac(byte[] data) throws NoSuchAlgorithmException, IOException {
        int numberOfBlocks = data.length%byteBlockSize == 0 ? getValueOfBlocks(data.length):getValueOfBlocks(data.length)+1;
        for (int i = 0; i < numberOfBlocks; ++i) {
            MacAddBlock(getBlock(i,data));
        }
        return MacFinalize();
    }


    private byte[] getBlock(int number, byte[] data) {
        if(number == -1)
            return Arrays.copyOfRange(data, (data.length / byteBlockSize - 1) * byteBlockSize, data.length);
        return Arrays.copyOfRange(data, number * byteBlockSize, (number + 1) * byteBlockSize);
    }

    private int getValueOfBlocks(int length) {
        return length / byteBlockSize;
    }
    private void countKeys() {
        keyOne = makeCalculationsToGainKeyHMAC1(key);
        keyTwo = makeCalculationsToGainKeyHMAC2(key);
    }

    private byte[] makeCalculationsToGainKeyHMAC1(byte[] array) {
        byte[] ipad = new byte[byteBlockSize];
        for (int i = 0; i < byteBlockSize; ++i) {
            ipad[i] = (byte) 0x36;
        }
        XOR.CountResult(ipad, array);
        return ipad;
    }

    private byte[] makeCalculationsToGainKeyHMAC2(byte[] array) {
        byte[] opad = new byte[byteBlockSize];
        for (int i = 0; i < byteBlockSize; ++i) {
            opad[i] = (byte) 0x5c;
        }
        XOR.CountResult(opad, array);
        return opad;
    }

    private byte[] getZerosByteArray() {
        byte[] zeros = new byte[byteBlockSize];
        for (int i = 0; i < byteBlockSize; ++i) {
            zeros[i] = (byte) 0;
        }
        return zeros;
    }
}
