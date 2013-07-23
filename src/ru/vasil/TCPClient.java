package ru.vasil;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import ru.vasil.message.Message;
import ru.vasil.message.MessageBuilder;
import ru.vasil.message.ResPQMessage;

import java.nio.ByteOrder;
import java.util.Random;

/**
 * @author Vasil
 */
public class TCPClient {
    private static Logger log = Logger.getLogger(TCPClient.class);

    public static void main(String[] args) throws Exception {
        configureLog4j();
        long timestamp = (System.currentTimeMillis() / 1000) << 32;
        SocketMessenger messenger = new SocketMessenger("95.142.192.65", 80);
//        messenger.write(new ReqPQMessage());
        byte[] temp = new byte[16];
        new Random().nextBytes(temp);
        messenger.write(MessageBuilder.aMessageBuilder()
                .withLong(0L).withLong(timestamp).withNextLength().withInt(0x60469778)
                .withBytes(temp).build(true, true)
        );
        ResPQMessage message = (ResPQMessage) messenger.read();
        int q = Message.getQ(message.pq);
        int p = (int) (message.pq / q);
        byte[] indent = {0, 0, 0};
        byte[] rand = new byte[32];
        new Random().nextBytes(rand);
        timestamp = (System.currentTimeMillis() / 1000) << 32;
        byte[] forEncode = MessageBuilder.aMessageBuilder().withInt(0x83c95aec)
                .withBytes((byte)0x08).withLong(message.pq, ByteOrder.BIG_ENDIAN).withBytes(indent)
                .withBytes((byte) 0x04).withInt(p,ByteOrder.BIG_ENDIAN).withBytes(indent)
                .withBytes((byte) 0x04).withInt(q, ByteOrder.BIG_ENDIAN).withBytes(indent)
                .withBytes(message.clientNonce).withBytes(message.serverNonce)
                .withBytes(rand).build(false, false);
        byte[] encoded = ResPQMessage.encode(forEncode);
        byte[] mes = MessageBuilder.aMessageBuilder()
                .withLong(0L).withLong(timestamp).withNextLength().withInt(0xd712e4be)
                .withBytes(message.clientNonce).withBytes(message.serverNonce)
                .withBytes((byte) 0x04).withInt(p, ByteOrder.BIG_ENDIAN).withBytes(indent)
                .withBytes((byte) 0x04).withInt(q, ByteOrder.BIG_ENDIAN).withBytes(indent)
                .withLong(message.fingerprints[0])
//                .withNextLength()
                .withBytes(new byte[]{(byte) 0xFE, 0, 1, 0})
                .withBytes(encoded).build(false, true);
        messenger.write(mes);
        messenger.read();
        messenger.close();
}

    private static void configureLog4j() {
        BasicConfigurator.configure(new ConsoleAppender(
                new PatternLayout("%d [%t] %p %c %x %m%n")));
    }
}
