package ru.vasil.message;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import ru.vasil.SocketMessenger;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Vasil
 */
public abstract class Message {
    protected final Logger log = Logger.getLogger(getClass());
    private static final Logger LOG = Logger.getLogger(Message.class);
    private static final char[] HEX_ARRAY = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    private static final Map<Integer, MessageBuilder> ANSWERS = new HashMap<Integer, MessageBuilder>() {{
        put(ResPQMessage.CONSTRUCTOR_NUMBER, new MessageBuilder() {
            @Override
            public Message build(byte[] message, int length) {
                return new ResPQMessage(message, length);
            }
        });
    }};

    public static int parseHeader(byte[] header) {
        StringBuilder builder = new StringBuilder("Header FROM:");
        ByteBuffer buffer = ByteBuffer.wrap(header);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        builder.append("\nTCP header: 0x");
        byte length = buffer.get();
        appendHexByte(builder, length);
        builder.append(", expected header+message length ").append(length*4);
        long authKeyId = buffer.getLong();
        long messageId = buffer.getLong();
        int messageLength = buffer.getInt();
        builder.append("\nauth_key_id: 0x").append(Long.toHexString(authKeyId).toUpperCase());
        builder.append("\nmessage_id: 0x").append(Long.toHexString(messageId).toUpperCase());
        builder.append("\nmessage_length: ").append(messageLength);
        builder.append(SocketMessenger.print(header, "Header bytes: "));
        LOG.info(builder);
        return messageLength;
    }

    public static Message parseMessage(byte[] message, int length) {
        ByteBuffer buffer = ByteBuffer.wrap(message);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int constructorNumber = buffer.getInt();
        return ANSWERS.get(constructorNumber).build(message, length);
    }

    public static void appendHexBytes(StringBuilder builder, byte... bytes) {
        for (byte b : bytes) {
            builder.append(HEX_ARRAY[b >>> 4 & 0x0F]).append(HEX_ARRAY[b & 0x0F]);
            builder.append(" ");
        }
    }

    public static void appendHexByte(StringBuilder builder, byte b) {
        builder.append(HEX_ARRAY[b >>> 4 & 0x0F]).append(HEX_ARRAY[b & 0x0F]);
    }

    public abstract byte[] getBytes();

    public static void main(String[] args) throws Exception {
        BasicConfigurator.configure();
        LOG.info(SocketMessenger.print(new ReqPQMessage().getBytes(), ""));
    }

    private interface MessageBuilder {
        Message build(byte[] message, int length);
    }
}
