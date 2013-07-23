package ru.vasil;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import ru.vasil.message.ReqPQMessage;

import java.io.IOException;
import java.math.BigInteger;

/**
 * @author Vasil
 */
public class TCPClient {
    private static Logger log = Logger.getLogger(TCPClient.class);

//    public static void main(String[] args) throws IOException {
//        configureLog4j();
//        SocketMessenger messenger = new SocketMessenger("95.142.192.65", 80);
//        messenger.write(new ReqPQMessage());
//        messenger.read();
//        messenger.close();
//}

    private static void configureLog4j() {
        BasicConfigurator.configure(new ConsoleAppender(
                new PatternLayout("%d [%t] %p %c %x %m%n")));
    }

    public static void main(String[] args) {
        Long pq = Long.parseLong("1C B1 98 CE 7B 47 A4 2F".replace(" ", ""), 16);
        for (int i = (int) Math.sqrt(pq); i > 0; i--) {
            if (pq % i == 0) {
                boolean fail = false;
                for (int k = 2; k < i / 2; k++) {
                    if (i % k == 0) {
                        fail = true;
                        break;
                    }
                }
                if (fail) continue;
                int q = (int) (pq / i);
                for (int k = 2; k < q / 2; k++) {
                    if (i % k == 0) {
                        fail = true;
                        break;
                    }
                }
                if (!fail) {
                    System.out.println(i + " " + q);
                    return;
                }
            }
        }
    }
}
