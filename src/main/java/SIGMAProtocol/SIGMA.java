package SIGMAProtocol;

public interface SIGMA {

    public  static void organiseProtocolConnection(User userFrom, User userTo){
        String mes = userFrom.startSession();
        mes = userTo.giveResponse(mes);
        mes = userFrom.finaliseConnection(mes);
        if(! userTo.doFinalVerificationWithProtocol(mes)){
            throw new RuntimeException("Failed connection throught SIGMA protocol");
        }
    }

}