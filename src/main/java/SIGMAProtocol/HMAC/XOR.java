package SIGMAProtocol.HMAC;

public interface XOR {
    static void CountResult(byte[] arr1, byte[] arr2){
        if(arr1 == null || arr2 == null || arr2.length!=arr1.length) return;
        for(int i=0;i<arr1.length;++i){
            arr1[i] = (byte)(arr1[i] ^ arr2[i]);
        }
    }
}
