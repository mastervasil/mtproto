package ru.vasil;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import ru.vasil.message.Message;
import ru.vasil.message.MessageBuilder;
import ru.vasil.message.ResPQMessage;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;

/**
 * @author Vasil
 */
public class TCPClient {
    private static Logger log = Logger.getLogger(TCPClient.class);

    public static void main(String[] args) throws Exception {
        System.out.println(Integer.toHexString(336));
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
        Message messageWithEnc = messenger.read();
        ByteBuffer buffer = ByteBuffer.wrap(messageWithEnc.getBytes());
        buffer.position(40);
        byte[] encrypted = new byte[592];
        buffer.get(encrypted);
        log.info(SocketMessenger.print(encrypted, "Encrypted"));
        Message.GPrime gPrime = Message.getGPrime(encrypted, message.clientNonce, message.serverNonce, rand);
        byte[] forB = new byte[2048];
        new Random().nextBytes(forB);
        BigInteger b = new BigInteger(1, forB);
        BigInteger gB = gPrime.g.modPow(b, gPrime.dhPrime);
        log.info("gB: " + gB);

        byte[] data = new byte[328-24];
        buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(0x6643b654).put(message.clientNonce).put(message.serverNonce).put(new byte[8])
                .put(new byte[] {(byte) 0xFE, 0, 1, 0})
                .put(gB.toByteArray());
        timestamp = (System.currentTimeMillis() / 1000) << 32;
        messenger.write(
                MessageBuilder.aMessageBuilder()
                        .withLong(0L).withLong(timestamp).withNextLength().withInt(0xf5045f1f)
                        .withBytes(message.clientNonce).withBytes(message.serverNonce)
                        .withBytes(new byte[]{(byte) 0xFE, 0x50, 1, 0})
                        .withBytes(Message.encode(data))
                        .build(false, true)
        );
        Message paramsMessage = messenger.read();
        byte[] newNonce = new byte[16];
        buffer = ByteBuffer.wrap(paramsMessage.getBytes());
        buffer.get(new byte[36]);
        buffer.get(newNonce);
        log.info(SocketMessenger.print(newNonce, "New nonce"));
        messenger.close();
}

    private static void configureLog4j() {
        BasicConfigurator.configure(new ConsoleAppender(
                new PatternLayout("%d [%t] %p %c %x %m%n")));
    }
}
