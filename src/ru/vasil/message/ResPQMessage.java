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
    public final byte[] clientNonce;
    public final byte[] serverNonce;
    public final long pq;
    public final long[] fingerprints;

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
        clientNonce = nonce;
        builder.append("\nClient nonce: ");
        appendHexBytes(builder, nonce);
        nonce = new byte[16];
        buffer.get(nonce);
        serverNonce = nonce;
        builder.append("\nServer nonce: ");
        appendHexBytes(builder, nonce);
        byte pqLength = buffer.get();
//        byte[] pq = new byte[pqLength];
//        buffer.get(pq);
//        this.pq = 0L;
        buffer.order(ByteOrder.BIG_ENDIAN);
        pq = buffer.getLong();
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 3; i++) {
            buffer.get();
        }
        builder.append("\nPQ: 0x").append(Long.toHexString(pq));
        int vectorConstructor = buffer.getInt();
        System.out.println(SocketMessenger.print(message, length, ""));
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
//        String s = "ec5ac9830817ED48941A08F98100000004494C553B00000004539110730000003E0549" +
//                "828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA573907330" +
//                "311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D" +
//                "b47530bac4e6c4387a62e1b30e8de319f1588e83";
//        byte[] bytes = hexStringToByteArray(s);
//        encode(bytes);
        String s = "MIIBCgKCAQEAwVACPi9w23mF3tBkdZz+zwrzKOaaQdr01vAbU4E1pvkfj4sqDsm6" +
                "lyDONS789sVoD/xCS9Y0hkkC3gtL1tSfTlgCMOOul9lcixlEKzwKENj1Yz/s7daS" +
                "an9tqw3bfUV/nqgbhGX81v/+7RFAEd+RwFnK7a+XYl9sluzHRyVVaTTveB2GazTw" +
                "Efzk2DWgkBluml8OREmvfraX3bkHZJTKX4EQSjBbbdJ2ZXIsRrYOXfaA+xayEGB+" +
                "8hdlLmAjbCVfaigxX0CDqWeR1yFL9kwd9P0NsZRPsmoqVwMbMu7mStFai6aIhc3n" +
                "Slv8kg9qv1m6XHVQY3PnEw+QQtqSIXklHwIDAQAB";
        System.out.println(s.length());
        System.out.println(0x100fe);

    }

    static String RSA_MODULUS = "C150023E2F70DB7985DED064759CFECF0AF328E69A41DAF4D6F01B538135A6F91F8F8B2A0EC9BA9720CE352EFCF6C5680FFC424BD634864902DE0B4BD6D49F4E580230E3AE97D95C8B19442B3C0A10D8F5633FECEDD6926A7F6DAB0DDB7D457F9EA81B8465FCD6FFFEED114011DF91C059CAEDAF97625F6C96ECC74725556934EF781D866B34F011FCE4D835A090196E9A5F0E4449AF7EB697DDB9076494CA5F81104A305B6DD27665722C46B60E5DF680FB16B210607EF217652E60236C255F6A28315F4083A96791D7214BF64C1DF4FD0DB1944FB26A2A57031B32EEE64AD15A8BA68885CDE74A5BFC920F6ABF59BA5C75506373E7130F9042DA922179251F";
    static String RSA_EXPONENT = "010001";

    public static byte[] encode(byte[] bytes) throws Exception {
        System.out.println(bytes.length);
        System.out.println(SocketMessenger.print(bytes, ""));
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] hash = sha1.digest(bytes);
        System.out.println(SocketMessenger.print(hash, ""));
        ByteBuffer buffer = ByteBuffer.allocate(255);
        buffer.put(hash).put(bytes);
        bytes = buffer.array();
        System.out.println("Array for encoding size: " + bytes.length);

//        BigInteger modulus = new BigInteger("24403446649145068056824081744112065346446136066297307473868293895086332508101251964919587745984311372853053253457835208829824428441874946556659953519213382748319518214765985662663680818277989736779506318868003755216402538945900388706898101286548187286716959100102939636333452457308619454821845196109544157601096359148241435922125602449263164512290854366930013825808102403072317738266383237191313714482187326643144603633877219028262697593882410403273959074350849923041765639673335775605842311578109726403165298875058941765362622936097839775380070572921007586266115476975819175319995527916042178582540628652481530373407");
//        BigInteger exp = new BigInteger("65537", 10);
        BigInteger modulus = new BigInteger(RSA_MODULUS, 16);
        BigInteger exp = new BigInteger(RSA_EXPONENT, 16);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exp);
        RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherData = cipher.doFinal(bytes);
//        BigInteger data = new BigInteger(1, bytes);
//        byte[] cipherData = data.modPow(exp, modulus).toByteArray();
//        if (cipherData.length == 257) {
//            ByteBuffer b = ByteBuffer.allocate(256);
//            b.put(cipherData, 1, 256);
//        }
//        System.out.println("ENCODED SIZE: " + cipherData.length);
        System.out.println(SocketMessenger.print(cipherData, ""));
        return cipherData;
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
