package ru.vasil.message;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import ru.vasil.SocketMessenger;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * @author lili
 */
public class MessageBuilder {
    private final Logger log = Logger.getLogger(getClass());
    private final List<MessagePart> parts = new ArrayList<MessagePart>();

    private MessageBuilder() {}

    public static MessageBuilder aMessageBuilder() {
        return new MessageBuilder();
    }

    public MessageBuilder withLong(final Long l) {
        return withLong(l, ByteOrder.LITTLE_ENDIAN);
    }

    public MessageBuilder withLong(final Long l, ByteOrder order) {
        parts.add(new MessagePart("Long", order, l, 8) {
            @Override
            void putData(ByteBuffer buffer) {
                buffer.putLong(l);
            }

            @Override
            public String dataToString() {
                return "0x" + Long.toHexString(l);
            }
        });
        return this;
    }

    public MessageBuilder withInt(Integer i) {
        return withInt(i, ByteOrder.LITTLE_ENDIAN);
    }

    public MessageBuilder withInt(final Integer i, ByteOrder order) {
        parts.add(new MessagePart("Int", order, i, 4) {
            @Override
            void putData(ByteBuffer buffer) {
                buffer.putInt(i);
            }

            @Override
            public String dataToString() {
                return "0x" + Integer.toHexString(i);
            }
        });
        return this;
    }

    public MessageBuilder withBytes(final byte... bytes) {
        parts.add(new MessagePart("Bytes", ByteOrder.LITTLE_ENDIAN, bytes, bytes.length) {
            @Override
            void putData(ByteBuffer buffer) {
                buffer.put(bytes);
            }

            @Override
            public String dataToString() {
                StringBuilder builder = new StringBuilder();
                Message.appendHexBytes(builder, bytes);
                return builder.toString();
            }
        });
        return this;
    }

    public MessageBuilder withNextLength() {
        parts.add(new MessagePart("Next bytes length", ByteOrder.LITTLE_ENDIAN, 0, 4) {
            private int nextLength;
            @Override
            void putData(ByteBuffer buffer) {
                createNextLength();
                buffer.putInt(nextLength);
            }

            private void createNextLength() {
                if (nextLength == 0) {
                    for (MessagePart part : parts) {
                        nextLength += part.length;
                    }
                }
            }

            @Override
            public String dataToString() {
                createNextLength();
                return "0x" + Integer.toHexString(nextLength);
            }
        });
        return this;
    }

    public byte[] build(boolean first, boolean withTcpHeader) {
        StringBuilder builder = new StringBuilder("Message built:");
        int length = first ? 2 : 1;
        if (!withTcpHeader) length--;
        for (MessagePart part : parts) {
            length += part.length;
        }
        if (length > 0x7e * 4) {
            length += 3;
        }

        ByteBuffer buffer = ByteBuffer.allocate(length);
        if (first) {
            builder.append("\nFirst message, added 0xEF");
            buffer.put((byte) 0xEF);
        }
        if (withTcpHeader) {
            if (length > 0x7e * 4) {
                length = length / 4 - 1;
                buffer.put((byte) 0x7f);
                buffer.put((byte) (length % 0x100));
                buffer.put((byte) (length / 0x100));
                buffer.put((byte) 0);
                builder.append("\nLength in 4-bytes format: 0x7e ");
                Message.appendHexBytes(builder, (byte) (length % 0x100), (byte) (length / 0x100));
            } else {
                byte header = (byte) (length / 4);
                builder.append("\nLength: 0x");
                Message.appendHexByte(builder, header);
                buffer.put(header);
            }
        }
        for (Iterator<MessagePart> iterator = parts.iterator(); iterator.hasNext(); ) {
            MessagePart part = iterator.next();
            iterator.remove();
            builder.append("\n").append(part.toString());
            part.put(buffer);
        }
        for (MessagePart part : parts) {
            builder.append("\n").append(part.toString());
            part.put(buffer);
        }
        byte[] array = buffer.array();
        builder.append(SocketMessenger.print(array, ""));
        log.info(builder.toString());
        return array;
    }

    private abstract class MessagePart {
        final ByteOrder order;
        final Object data;
        final int length;
        final String name;

        MessagePart(String name, ByteOrder order, Object data, int length) {
            this.name = name;
            this.order = order;
            this.data = data;
            this.length = length;
        }

        void put(ByteBuffer buffer) {
            buffer.order(order);
            putData(buffer);
        }

        @Override
        public String toString() {
            return name + ": " + dataToString();
        }

        abstract void putData(ByteBuffer buffer);
        public abstract String dataToString();
    }

    public static void main(String[] args) {
        BasicConfigurator.configure();
        Long timestamp = System.currentTimeMillis() / 1000 << 32;
        byte[] bytes = aMessageBuilder().withLong(0L).withLong(timestamp).withNextLength()
                .withInt(0x60469778).withBytes(new BigInteger("3E0549828CCA27E966B301A48FECE2FC", 16).toByteArray()).build(true, true);
    }
}
