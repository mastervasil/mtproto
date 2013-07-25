package ru.vasil;

import org.apache.log4j.Logger;
import ru.vasil.message.Message;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * @author Vasil
 */
public class SocketMessenger {
    private static final Logger log = Logger.getLogger(SocketMessenger.class);
    private static final int BUFFER_SIZE = 1024;
    private static final byte FIRST_HEADER = (byte) 0xEF;
    private final OutputStream out;
    private final InputStream in;
    private final Socket socket;
    private final byte[] HEADER_BUFFER = new byte[20];
    private final byte[] BUFFER = new byte[BUFFER_SIZE];

    private boolean firstWrite = true;

    public SocketMessenger(String host, int port) throws IOException {
        socket = new Socket(host, port);
        out = socket.getOutputStream();
        in = socket.getInputStream();
    }

    public void close() throws IOException {
        socket.close();
    }

    public void write(Message message) throws IOException {
        byte[] bytes = message.getBytes();
        log.info(print(bytes, "Message TO:"));
        writeFirstTCPHeader();
        out.write(bytes);
    }

    public void write(byte[] bytes) throws IOException {
        log.info(print(bytes, "Message TO:"));
        out.write(bytes);
    }

    private void writeFirstTCPHeader() throws IOException {
        if (firstWrite) {
            out.write(FIRST_HEADER);
            firstWrite = false;
        }
    }

    public Message read() throws IOException {
        byte[] tcpHeader = new byte[1];
        in.read(tcpHeader);
        if (tcpHeader[0] == 0x7f) {
            tcpHeader = new byte[3];
            in.read(tcpHeader);
        }
        int read = in.read(HEADER_BUFFER);
        if (read != 20) {
            log.error(print(HEADER_BUFFER, "Malformed header with size " + read));
            throw new RuntimeException("Malformed header received");
        }
        int length = Message.parseHeader(HEADER_BUFFER, tcpHeader);
        byte[] buffer = BUFFER;
        if (length > BUFFER_SIZE) {
//            buffer = new byte[length];
            log.warn("Using big buffer with size " + length);
        }
        read = in.read(buffer);
        if (read != length) {
            log.error(print(buffer, "Malformed message with size " + read + ", expected " + length));
            throw new RuntimeException("Malformed message received");
        }
        return Message.parseMessage(buffer, length);
    }


    public static String print(byte[] bytes, String type) {
        return print(bytes, bytes.length, type);
    }

    public static String print(byte[] bytes, int length, String type) {
        StringBuilder builder = new StringBuilder("\n" + type);
        for (int i = 0; i < length; i++) {
            if (i % 0x10 == 0) {
                builder.append(String.format("\n%04x | ", i));
            }
            builder.append(String.format("%02x ", bytes[i]));
        }
        builder.append("\n");
        return builder.toString();
    }

}
