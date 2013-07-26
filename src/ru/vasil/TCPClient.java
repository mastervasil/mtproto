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
import java.util.Arrays;
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
        byte[] newNonce = new byte[32];
        new Random().nextBytes(newNonce);
        timestamp = (System.currentTimeMillis() / 1000) << 32;
        byte[] forEncode = MessageBuilder.aMessageBuilder().withInt(0x83c95aec)
                .withBytes((byte)0x08).withLong(message.pq, ByteOrder.BIG_ENDIAN).withBytes(indent)
                .withBytes((byte) 0x04).withInt(p,ByteOrder.BIG_ENDIAN).withBytes(indent)
                .withBytes((byte) 0x04).withInt(q, ByteOrder.BIG_ENDIAN).withBytes(indent)
                .withBytes(message.clientNonce).withBytes(message.serverNonce)
                .withBytes(newNonce).build(false, false);
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
        Message.GPrime gPrime = Message.getGPrime(encrypted, message.clientNonce, message.serverNonce, newNonce);
        byte[] forB = new byte[2048];
        new Random().nextBytes(forB);
        BigInteger b = new BigInteger(1, forB);
        BigInteger gB = gPrime.g.modPow(b, gPrime.dhPrime);
        String gBString = gB.toString(16);
        log.info("gB: length=" + gBString.length() + "\n" + gBString);

        byte[] data = new byte[328-24];
        buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(0x6643b654).put(message.clientNonce).put(message.serverNonce).put(new byte[8])
                .put(new byte[] {(byte) 0xFE, 0, 1, 0})
                .put(Message.trim(gB));
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
        byte[] newNonceHash1 = new byte[16];
        buffer = ByteBuffer.wrap(paramsMessage.getBytes());
        buffer.get(new byte[36]);
        buffer.get(newNonceHash1);
        byte[] gAB = Message.trim(gPrime.gA.modPow(b, gPrime.dhPrime));
        System.out.println("gAB length: " + gAB.length);
        System.out.println(SocketMessenger.print(gAB, "gAB"));
        log.info(SocketMessenger.print(newNonceHash1, "New nonce hash 1"));
        buffer = ByteBuffer.allocate(newNonce.length + 1 + 8);
        byte[] gABSha1 = Message.getSHA1(gAB);
        buffer.put(newNonce).put((byte) 1).put(gABSha1, 0, 8);
        System.out.println(SocketMessenger.print(Message.getSHA1(buffer.array()), "New nonce hash 1 +"));
        byte[] salt = Message.xor(Arrays.copyOfRange(newNonce, 0, 8), Arrays.copyOfRange(message.serverNonce, 0, 8));
//        buffer = ByteBuffer.allocate(salt.length);
//        for (int i = salt.length - 1; i >= 0; i--) {
//            buffer.put(salt[i]);
//        }
//        salt = buffer.array();
        byte[] sessionId = new byte[8];
        int seqNo = 1;
        int vkId = 156073;
        int age = 23;
        byte[] name = Message.wrapString("Василь Иванов".getBytes());
        byte[] phoneNumber = Message.wrapString("+79269146491".getBytes());
        byte[] city = Message.wrapString("Москва".getBytes());
        timestamp = (System.currentTimeMillis() / 1000) << 32;
//        timestamp += 4;
        sessionId[0] = 1;
        System.out.println(SocketMessenger.print(salt, "Salt"));
        byte[] forEncWithoutPadding = MessageBuilder.aMessageBuilder().withBytes(salt).withBytes(sessionId)
                .withLong(timestamp).withInt(seqNo).withNextLength().withInt(0x9a5f6e95)
                .withInt(vkId).withBytes(name).withBytes(phoneNumber).withInt(age).withBytes(city).build(false, false);
        int padding = 0;
        while ((forEncWithoutPadding.length + padding) % 16 != 0) padding++;
        byte[] forEnc = ByteBuffer.allocate(forEncWithoutPadding.length + padding).
                put(forEncWithoutPadding).put(new byte[padding]).array();
        System.out.println("For encryption size: " + forEnc.length);
        byte[] msgKey = Arrays.copyOfRange(Message.getSHA1(forEncWithoutPadding), 4, 4+16);
        byte[] authKeyId = Arrays.copyOfRange(gABSha1, 12, 12+8);
        System.out.println(SocketMessenger.print(gABSha1,"SHA1 of gAB"));
        System.out.println(SocketMessenger.print(authKeyId,"authKeyId"));
        byte[] sha1_a = Message.getSHA1(ByteBuffer.allocate(msgKey.length + 32)
            .put(msgKey).put(gAB, 0, 32).array());
        byte[] sha1_b = Message.getSHA1(ByteBuffer.allocate(16 + msgKey.length + 16)
            .put(gAB, 32, 16).put(msgKey).put(gAB, 48, 16).array());
        byte[] sha1_c = Message.getSHA1(ByteBuffer.allocate(32 + msgKey.length)
            .put(gAB, 64, 32).put(msgKey).array());
        byte[] sha1_d = Message.getSHA1(ByteBuffer.allocate(msgKey.length + 32)
            .put(msgKey).put(gAB, 96, 32).array());
        byte[] aes_key = ByteBuffer.allocate(8 + 12 + 12).put(sha1_a, 0, 8).put(sha1_b, 8, 12).put(sha1_c, 4, 12).array();
        byte[] aes_iv = ByteBuffer.allocate(12 + 8 + 4 + 8).put(sha1_a, 8, 12).put(sha1_b, 0, 8)
                .put(sha1_c, 16, 4).put(sha1_d, 0, 8).array();
        encrypted = Message.encode(forEnc, aes_key, aes_iv);
        messenger.write(MessageBuilder.aMessageBuilder().withBytes(authKeyId).withBytes(msgKey)
                /*.withBytes((byte) encrypted.length)*/.withBytes(encrypted)/*.withBytes(new byte[3])*/
                .build(false, true));
        messenger.read();
        messenger.close();
}

    private static void configureLog4j() {
        BasicConfigurator.configure(new ConsoleAppender(
                new PatternLayout("%d [%t] %p %c %x %m%n")));
    }
}
