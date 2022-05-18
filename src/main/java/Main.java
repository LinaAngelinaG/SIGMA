import SIGMAProtocol.SIGMA;
import SIGMAProtocol.User;

public class Main {
    public static void main(String[] args) {
        User userA = new User();
        User userB = new User();
        SIGMA.organiseProtocolConnection(userA,userB);
    }
}
