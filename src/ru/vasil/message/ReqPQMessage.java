package ru.vasil.message;

import org.apache.log4j.Logger;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Random;

/**
 * @author Vasil
 */
public class ReqPQMessage extends Message {
    private static final int CONSTRUCTOR_NUMBER = 0x60469778;
    private static final byte TCP_HEADER = 40 / 4;
    private static final long AUTH_KEY_ID = 0L;
    private static final int MESSAGE_LENGTH = 20;
    private static final String SIGNATURE = "req_pq#60469778 nonce:int128 = ResPQ";

    @Override
    public byte[] getBytes() {
        ByteBuffer byteBuffer = ByteBuffer.allocate(41);
        StringBuilder builder = new StringBuilder("Creating REQ_PQ message:");
        builder.append("\nMethod signature: ").append(SIGNATURE);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        builder.append("\nTCP header: 0x" + TCP_HEADER);
        byteBuffer.put(TCP_HEADER);
        builder.append("\nauth_key_id: 0x").append(Long.toHexString(AUTH_KEY_ID).toUpperCase());
        byteBuffer.putLong(AUTH_KEY_ID);
        long timestamp = System.currentTimeMillis() / 1000;
        builder.append("\nmessage_id: 0x").append(Long.toHexString(timestamp).toUpperCase());
        byteBuffer.putLong(timestamp << 32);
        builder.append("\nmessage_length: ").append(MESSAGE_LENGTH);
        byteBuffer.putInt(MESSAGE_LENGTH);
        builder.append("\nConstructor number: 0x").append(Long.toHexString(CONSTRUCTOR_NUMBER).toUpperCase());
        byteBuffer.putInt(CONSTRUCTOR_NUMBER);
        byte[] nonce = new byte[16];
        new Random(timestamp).nextBytes(nonce);
        builder.append("\nNonce: ");
        appendHexBytes(builder, nonce);
        builder.append("\n");
        byteBuffer.put(nonce);
        log.info(builder.toString());
        return byteBuffer.array();
    }


    public static void main(String[] args) {
        byte[] bytes = new BigInteger("100").toByteArray();
        System.out.println(Arrays.toString(bytes));
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            appendHexByte(builder, b);
            builder.append(" ");
        }
        System.out.println(builder);
        System.out.println(Integer.toHexString(100));
    }

}
