package ru.vasil;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import ru.vasil.message.ReqPQMessage;

import java.io.IOException;

/**
 * @author Vasil
 */
public class TCPClient {
    private static Logger log = Logger.getLogger(TCPClient.class);
//    private static final byte[] request = new byte[] {(byte) 0xef, 0x0a,
//0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xC4, 0x7A, (byte) 0xE5, 0x51,
//0x14, 0x00, 0x00, 0x00, 0x78, (byte) 0x97, 0x46, 0x60, 0x3E, 0x05, 0x49, (byte) 0x82, (byte) 0x8C, (byte) 0xCA, 0x27, (byte) 0xE9,
//0x66, (byte) 0xB3, 0x01, (byte) 0xA4, (byte) 0x8F, (byte) 0xEC, (byte) 0xE2, (byte) 0xFB
//    };

    public static void main(String[] args) throws IOException {
        configureLog4j();
        SocketMessenger messenger = new SocketMessenger("95.142.192.65", 80);
        messenger.write(new ReqPQMessage());
        messenger.read();
        messenger.close();

    }

    private static void configureLog4j() {
        BasicConfigurator.configure(new ConsoleAppender(
                new PatternLayout("%d [%t] %p %c %x %m%n")));
    }
}
