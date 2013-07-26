package ru.vasil.message;

import org.apache.log4j.Logger;
import ru.vasil.SocketMessenger;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
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

    public static int parseHeader(byte[] header, byte[] tcpHeader) {
        StringBuilder builder = new StringBuilder("Header FROM:");
        ByteBuffer buffer = ByteBuffer.wrap(header);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        builder.append("\nTCP header: 0x");
        appendHexBytes(builder, tcpHeader);
//        byte length = buffer.get();
//        appendHexByte(builder, length);
//        builder.append(", expected header+message length ").append(length*4);
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

    public static Message parseMessage(final byte[] message, int length) {
        ByteBuffer buffer = ByteBuffer.wrap(message);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int constructorNumber = buffer.getInt();
        MessageBuilder messageBuilder = ANSWERS.get(constructorNumber);
        if (messageBuilder == null) {
            LOG.info(SocketMessenger.print(message, length, "UNKNOWN MESSAGE"));
            return new Message() {
                @Override
                public byte[] getBytes() {
                    return message;
                }
            };
        }
        return messageBuilder.build(message, length);
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

    public static int getQ(long pq) {
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
                    return q;
                }
            }
        }
        throw new RuntimeException("Failed to find Q from 0x" + Long.toHexString(pq));
    }

    private interface MessageBuilder {
        Message build(byte[] message, int length);
    }

    public static byte[] tmpAesKey;
    public static byte[] tmpAesIv;

    public static GPrime getGPrime(byte[] encrypted, byte[] clientNonce, byte[] serverNonce, byte[] newNonce) throws Exception {
//        String encryptedString = "28A92FE20173B347A8BB324B5FAB2667C9A8BBCE6468D5B509A4CBDDC186240AC912CF7006AF8926DE606A2E74C0493CAA57741E6C82451F54D3E068F5CCC49B4444124B9666FFB405AAB564A3D01E67F6E912867C8D20D9882707DC330B17B4E0DD57CB53BFAAFA9EF5BE76AE6C1B9B6C51E2D6502A47C883095C46C81E3BE25F62427B585488BB3BF239213BF48EB8FE34C9A026CC8413934043974DB03556633038392CECB51F94824E140B98637730A4BE79A8F9DAFA39BAE81E1095849EA4C83467C92A3A17D997817C8A7AC61C3FF414DA37B7D66E949C0AEC858F048224210FCC61F11C3A910B431CCBD104CCCC8DC6D29D4A5D133BE639A4C32BBFF153E63ACA3AC52F2E4709B8AE01844B142C1EE89D075D64F69A399FEB04E656FE3675A6F8F412078F3D0B58DA15311C1A9F8E53B3CD6BB5572C294904B726D0BE337E2E21977DA26DD6E33270251C2CA29DFCC70227F0755F84CFDA9AC4B8DD5F84F1D1EB36BA45CDDC70444D8C213E4BD8F63B8AB95A2D0B4180DC91283DC063ACFB92D6A4E407CDE7C8C69689F77A007441D4A6A8384B666502D9B77FC68B5B43CC607E60A146223E110FCB43BC3C942EF981930CDC4A1D310C0B64D5E55D308D863251AB90502C3E46CC599E886A927CDA963B9EB16CE62603B68529EE98F9F5206419E03FB458EC4BD9454AA8F6BA777573CC54B328895B1DF25EAD9FB4CD5198EE022B2B81F388D281D5E5BC580107CA01A50665C32B552715F335FD76264FAD00DDD5AE45B94832AC79CE7C511D194BC42B70EFA850BB15C2012C5215CABFE97CE66B8D8734D0EE759A638AF013";
//        String clientNonceString = "3E0549828CCA27E966B301A48FECE2FC";
//        String serverNonceString = "A5CF4D33F4A11EA877BA4AA573907330";
//        String newNonceString = "311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D";
//        encrypted = ResPQMessage.hexStringToByteArray(encryptedString);
//        clientNonce = ResPQMessage.hexStringToByteArray(clientNonceString);
//        serverNonce = ResPQMessage.hexStringToByteArray(serverNonceString);
//        newNonce = ResPQMessage.hexStringToByteArray(newNonceString);

        byte[] newServerNonce = new byte[32+16];
        ByteBuffer buffer = ByteBuffer.wrap(newServerNonce);
        buffer.put(newNonce).put(serverNonce);
        byte[] serverNewNonce = new byte[32+16];
        buffer = ByteBuffer.wrap(serverNewNonce);
        buffer.put(serverNonce).put(newNonce);
        byte[] newNewNonce = new byte[32+32];
        buffer = ByteBuffer.wrap(newNewNonce);
        buffer.put(newNonce).put(newNonce);
        System.out.println(SocketMessenger.print(encrypted, "encrypted"));
        System.out.println(SocketMessenger.print(clientNonce, "cliend nonce"));
        System.out.println(SocketMessenger.print(serverNonce, "server nonce"));
        System.out.println(SocketMessenger.print(newNonce, "new nonce"));
        System.out.println(SocketMessenger.print(newServerNonce, "new + server nonce"));

        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] hashNS = sha1.digest(newServerNonce);
        tmpAesKey = new byte[32];
        buffer = ByteBuffer.wrap(tmpAesKey);
        buffer.put(hashNS);
        byte[] hashSN = sha1.digest(serverNewNonce);
        byte[] hashNN = sha1.digest(newNewNonce);
        buffer.put(hashSN, 0, 12);
        System.out.println(SocketMessenger.print(hashNS, "new + server nonce HASH"));
        System.out.println(SocketMessenger.print(tmpAesKey, "tmpAesKey"));

        tmpAesIv = new byte[32];
        buffer = ByteBuffer.wrap(tmpAesIv);
        buffer.put(hashSN, 12, 8).put(hashNN).put(newNonce, 0, 4);
        System.out.println(SocketMessenger.print(tmpAesIv, "tmpAesIv"));

//        tmpAesKey = ResPQMessage.hexStringToByteArray("F011280887C7BB01DF0FC4E17830E0B91FBB8BE4B2267CB985AE25F33B527253");
//        tmpAesIv = ResPQMessage.hexStringToByteArray("3212D579EE35452ED23E0D0C92841AA7D31B2E9BDEF2151E80D15860311C85DB");

        final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(tmpAesKey, "AES"));

        final int blocksize = cipher.getBlockSize();

        byte[] xPrev = Arrays.copyOfRange(tmpAesIv, 0, blocksize);
        byte[] yPrev = Arrays.copyOfRange(tmpAesIv, blocksize, tmpAesIv.length);

        byte[] decrypted = new byte[0];

        byte[] y, x;
        for (int i = 0; i < encrypted.length; i += blocksize) {
            x = java.util.Arrays.copyOfRange(encrypted, i, i + blocksize);
            y = xor(cipher.doFinal(xor(x, yPrev)), xPrev);
            xPrev = x;
            yPrev = y;

            decrypted = sumBytes(decrypted, y);
        }

        System.out.println(SocketMessenger.print(decrypted, "decrypted"));
        buffer = ByteBuffer.wrap(decrypted);
        buffer.position(24 + 32);
        GPrime gPrime = new GPrime(buffer);
        System.out.println(gPrime.toString());
        System.out.println("Encrypted length: " + encrypted.length);
        System.out.println("Decrypted length: " + decrypted.length);
        return gPrime;
    }

    public static class GPrime {
        public final BigInteger g;
        public final byte[] forDHPrime = new byte[256];
        public final BigInteger dhPrime;
        public final byte[] forGA = new byte[256];
        public final BigInteger gA;

        public GPrime(ByteBuffer buffer) {
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            this.g = new BigInteger(Integer.toString(buffer.getInt()));
            buffer.get();
            buffer.get();
            buffer.get();
            buffer.get();
            buffer.get(forDHPrime);
            buffer.get();
            buffer.get();
            buffer.get();
            buffer.get();
            buffer.get(forGA);
            dhPrime = new BigInteger(1, forDHPrime);
            gA = new BigInteger(1, forGA);
        }

        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("G: ").append(g)
                    .append("\ndhPrime : 0x");
            appendHexBytes(builder, forDHPrime);
            builder.append("\ngA: 0x");
            appendHexBytes(builder, forGA);
            return builder.toString();
        }
    }

    public static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new RuntimeException("Different lengths " + a.length + " " + b.length);
        }
        byte[] bytes = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            bytes[i] = (byte) (a[i] ^ b[i]);
        }
        return bytes;
    }

    public static byte[] sumBytes(byte[] a, byte[] b) {
        ByteBuffer buffer = ByteBuffer.allocate(a.length + b.length);
        return buffer.put(a).put(b).array();
    }

    public static byte[] wrapString(byte[] bytes) {
        if (bytes.length >= 254) {
            throw new RuntimeException("Implement me! " + bytes.length);
        }
        int padding = 0;
        while ((bytes.length + 1 + padding) % 4 != 0) {
            padding++;
        }
        ByteBuffer buffer = ByteBuffer.allocate(bytes.length + 1 + padding);
        buffer.put((byte) bytes.length).put(bytes);
        for (int i = 0; i < padding; i++) {
            buffer.put((byte) 0);
        }
        return buffer.array();
    }

    public static byte[] encode(byte[] data, byte[] aesKey, byte[] aesIv) throws Exception {
        tmpAesKey = aesKey;
        tmpAesIv = aesIv;
        return encode(data);
    }

    public static byte[] encode(byte[] data) throws Exception{
        ByteBuffer buffer;

//        String encryptedString = "28A92FE20173B347A8BB324B5FAB2667C9A8BBCE6468D5B509A4CBDDC186240AC912CF7006AF8926DE606A2E74C0493CAA57741E6C82451F54D3E068F5CCC49B4444124B9666FFB405AAB564A3D01E67F6E912867C8D20D9882707DC330B17B4E0DD57CB53BFAAFA9EF5BE76AE6C1B9B6C51E2D6502A47C883095C46C81E3BE25F62427B585488BB3BF239213BF48EB8FE34C9A026CC8413934043974DB03556633038392CECB51F94824E140B98637730A4BE79A8F9DAFA39BAE81E1095849EA4C83467C92A3A17D997817C8A7AC61C3FF414DA37B7D66E949C0AEC858F048224210FCC61F11C3A910B431CCBD104CCCC8DC6D29D4A5D133BE639A4C32BBFF153E63ACA3AC52F2E4709B8AE01844B142C1EE89D075D64F69A399FEB04E656FE3675A6F8F412078F3D0B58DA15311C1A9F8E53B3CD6BB5572C294904B726D0BE337E2E21977DA26DD6E33270251C2CA29DFCC70227F0755F84CFDA9AC4B8DD5F84F1D1EB36BA45CDDC70444D8C213E4BD8F63B8AB95A2D0B4180DC91283DC063ACFB92D6A4E407CDE7C8C69689F77A007441D4A6A8384B666502D9B77FC68B5B43CC607E60A146223E110FCB43BC3C942EF981930CDC4A1D310C0B64D5E55D308D863251AB90502C3E46CC599E886A927CDA963B9EB16CE62603B68529EE98F9F5206419E03FB458EC4BD9454AA8F6BA777573CC54B328895B1DF25EAD9FB4CD5198EE022B2B81F388D281D5E5BC580107CA01A50665C32B552715F335FD76264FAD00DDD5AE45B94832AC79CE7C511D194BC42B70EFA850BB15C2012C5215CABFE97CE66B8D8734D0EE759A638AF013";
//        String clientNonceString = "3E0549828CCA27E966B301A48FECE2FC";
//        String serverNonceString = "A5CF4D33F4A11EA877BA4AA573907330";
//        String newNonceString = "311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D";
//        String gBString = "FE00010073700E7BFC7AEEC828EB8E0DCC04D09A0DD56A1B4B35F72F0B55FCE7DB7EBB72D7C33C5D4AA59E1C74D09B01AE536B318CFED436AFDB15FE9EB4C70D7F0CB14E46DBBDE9053A64304361EB358A9BB32E9D5C2843FE87248B89C3F066A7D5876D61657ACC52B0D81CD683B2A0FA93E8ADAB20377877F3BC3369BBF57B10F5B589E65A9C27490F30A0C70FFCFD3453F5B379C1B9727A573CFFDCA8D23C721B135B92E529B1CDD2F7ABD4F34DAC4BE1EEAF60993DDE8ED45890E4F47C26F2C0B2E037BB502739C8824F2A99E2B1E7E416583417CC79A8807A4BDAC6A5E9805D4F6186C37D66F6988C9F9C752896F3D34D25529263FAF2670A09B2A59CE35264511F";
//        byte[] clientNonce = ResPQMessage.hexStringToByteArray(clientNonceString);
//        byte[] serverNonce = ResPQMessage.hexStringToByteArray(serverNonceString);
//        byte[] gB = ResPQMessage.hexStringToByteArray(gBString);
//        byte[] data = new byte[328-24];
//        buffer = ByteBuffer.wrap(data);
//        buffer.order(ByteOrder.LITTLE_ENDIAN);
//        buffer.putInt(0x6643b654).put(clientNonce).put(serverNonce).put(new byte[8]).put(gB);
//        System.out.println(SocketMessenger.print(data, "data"));

        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] dataHash = sha1.digest(data);
        System.out.println(dataHash.length + data.length);
        byte[] dataWithHash = new byte[dataHash.length + data.length + 12];
        buffer = ByteBuffer.wrap(dataWithHash);
        buffer.put(dataHash).put(data);

//        tmpAesKey = ResPQMessage.hexStringToByteArray("F011280887C7BB01DF0FC4E17830E0B91FBB8BE4B2267CB985AE25F33B527253");
//        tmpAesIv = ResPQMessage.hexStringToByteArray("3212D579EE35452ED23E0D0C92841AA7D31B2E9BDEF2151E80D15860311C85DB");

        final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(tmpAesKey, "AES"));

        final int blocksize = cipher.getBlockSize();

        byte[] xPrev = Arrays.copyOfRange(tmpAesIv, 0, blocksize);
        byte[] yPrev = Arrays.copyOfRange(tmpAesIv, blocksize, tmpAesIv.length);

        byte[] encrypted = new byte[0];

        byte[] y, x;
        System.out.println(blocksize);
        for (int i = 0; i < dataWithHash.length; i += blocksize) {
            x = java.util.Arrays.copyOfRange(dataWithHash, i, i + blocksize);
            y = xor(cipher.doFinal(xor(x, xPrev)), yPrev);
            xPrev = y;
            yPrev = x;

            encrypted = sumBytes(encrypted, y);
        }

        System.out.println(SocketMessenger.print(encrypted, ""));
        System.out.println(encrypted.length);
        return encrypted;
    }

    public static byte[] getSHA1(byte[] bytes, int offset, int length) throws NoSuchAlgorithmException {
        return getSHA1(ByteBuffer.allocate(length).put(bytes, offset, length).array());
    }

    public static byte[] getSHA1(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        return sha1.digest(bytes);
    }

    public static byte[] trim(BigInteger b) {
        byte[] bytes = b.toByteArray();
        if (bytes.length % 2 != 0) {
            ByteBuffer buffer = ByteBuffer.allocate(bytes.length - 1);
            buffer.put(bytes, 1, bytes.length - 1);
            return buffer.array();
        }
        return bytes;
    }
}
