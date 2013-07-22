package ru.vasil.message;

import ru.vasil.SocketMessenger;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 * @author Vasil
 */
public class ResPQMessage extends Message{
    public static final int CONSTRUCTOR_NUMBER = 0x05162463;
    public static final int VECTOR_CONSTRUCTOR_NUMBER = 0xc734a64e;
    private static final String SIGNATURE = "resPQ#05162463 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector long = ResPQ";
    private final BigInteger clientNonce;
    private final BigInteger serverNonce;
    private final byte[] pq;
    private final long[] fingerprints;

    public ResPQMessage(byte[] message, int length) {
        StringBuilder builder = new StringBuilder("New message FROM with type RES_PQ:");
        builder.append("\nMethod signature: ").append(SIGNATURE);
        ByteBuffer buffer = ByteBuffer.wrap(message);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int constructorNumber = buffer.getInt();
        checkConstructor(CONSTRUCTOR_NUMBER, constructorNumber);
        builder.append("\nConstructor number: 0x").append(Long.toHexString(CONSTRUCTOR_NUMBER).toUpperCase());
        byte[] nonce = new byte[16];
        buffer.get(nonce);
        clientNonce = new BigInteger(nonce);
        builder.append("\nClient nonce: ");
        appendHexBytes(builder, nonce);
        buffer.get(nonce);
        serverNonce = new BigInteger(nonce);
        builder.append("\nServer nonce: ");
        appendHexBytes(builder, nonce);
        byte pqLength = buffer.get();
        pq = new byte[pqLength];
        buffer.get(pq);
        for (int i = 0; i < 3; i++) {
            buffer.get();
        }
        builder.append("\nPQ: ");
        appendHexBytes(builder, pq);
        int vectorConstructor = buffer.getInt();
        checkConstructor(VECTOR_CONSTRUCTOR_NUMBER, vectorConstructor);
        builder.append("\nVector constructor number: 0x").append(Long.toHexString(VECTOR_CONSTRUCTOR_NUMBER).toUpperCase());
        int fingerprintsCount = buffer.getInt();
        builder.append("\nFingerprints count: ").append(fingerprintsCount);
        fingerprints = new long[fingerprintsCount];
        for (int i = 0; i < fingerprintsCount; i++) {
            fingerprints[i] = buffer.getLong();
            builder.append("\nFingerprints[").append(i).append("] = 0x");
            builder.append(Long.toHexString(fingerprints[i]).toUpperCase());
        }
        builder.append(SocketMessenger.print(message, length, "Message bytes: "));
        log.info(builder);

    }

    protected void checkConstructor(int expected, int actual) {
        if (expected != actual) {
            throw new RuntimeException("Wrong constructor number, expected "
                    + expected + ", but was " + actual);
        }
    }

    @Override
    public byte[] getBytes() {
        throw new UnsupportedOperationException();
    }


    public static void main(String[] args) throws Exception {
        String s = "ec5ac9830817ED48941A08F98100000004494C553B00000004539110730000003E0549" +
                "828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA573907330" +
                "311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D" +
                "b47530bac4e6c4387a62e1b30e8de319f1588e83";
        byte[] bytes = hexStringToByteArray(s);
        System.out.println(bytes.length);
        System.out.println(SocketMessenger.print(bytes, ""));
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] digest = sha1.digest(bytes);
        System.out.println(SocketMessenger.print(digest, ""));

        BigInteger modulus = new BigInteger("103520733050543171944230178451440850287782045556375006902412091947249265871685973328994843040318957286307359431601334384329628751139480899727286106977986905648743144574259726409398352563497403036830099863724180007380850219644569145240539428089005925399649588728160659518719888280841284207649644722908135056669");
        BigInteger exp = new BigInteger("010001", 16);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exp);
        RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherData = cipher.doFinal(bytes);
        System.out.println(SocketMessenger.print(cipherData, ""));


    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
