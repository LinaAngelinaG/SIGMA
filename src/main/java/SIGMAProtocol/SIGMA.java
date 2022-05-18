package SIGMAProtocol;

public interface SIGMA {

    public  static void organiseProtocolConnection(User userFrom, User userTo){
        String mes = userFrom.startSession();
        mes = userTo.giveResponse(mes);
        mes = userFrom.finaliseConnection(mes);
        if(userTo.doFinalVerificationWithProtocol(mes)){
            System.out.println("Success connection throught SIGMA protocol");
        }
    }

}