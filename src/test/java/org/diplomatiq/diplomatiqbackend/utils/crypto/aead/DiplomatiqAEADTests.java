package org.diplomatiq.diplomatiqbackend.utils.crypto.aead;

import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class DiplomatiqAEADTests {
    private void checkSerializationFormat(byte[] aeadBytes, boolean hasCiphertext, boolean hasAad) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(aeadBytes);

        int ivLength = byteArrayInputStream.read();
        int aadLength = ByteBuffer.wrap(byteArrayInputStream.readNBytes(4)).getInt();
        int ciphertextLength = ByteBuffer.wrap(byteArrayInputStream.readNBytes(4)).getInt();
        int tagLength = byteArrayInputStream.read();

        int expectedLength = 1 + 4 + 4 + 1 + ivLength + aadLength + ciphertextLength + tagLength;
        Assertions.assertEquals(expectedLength, aeadBytes.length);

        Assertions.assertTrue(hasCiphertext ? ciphertextLength > 0 : ciphertextLength == 0);
        Assertions.assertTrue(hasAad ? aadLength > 0 : aadLength == 0);
    }

    @Test
    public void onlyEncrypted() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] plaintext = RandomUtils.bytes(55);
        byte[] aad = new byte[0];

        byte[] key = RandomUtils.bytes(32);

        DiplomatiqAEAD toSerialize = new DiplomatiqAEAD(plaintext, aad);
        byte[] serializedBytes = toSerialize.toBytes(key);

        checkSerializationFormat(serializedBytes, true, false);

        DiplomatiqAEAD unserialized = DiplomatiqAEAD.fromBytes(serializedBytes, key);

        Assertions.assertArrayEquals(plaintext, unserialized.getPlaintext());
        Assertions.assertArrayEquals(aad, unserialized.getAad());
    }

    @Test
    public void onlyEncryptedSmall() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] plaintext = RandomUtils.bytes(1);
        byte[] aad = new byte[0];

        byte[] key = RandomUtils.bytes(32);

        DiplomatiqAEAD toSerialize = new DiplomatiqAEAD(plaintext, aad);
        byte[] serializedBytes = toSerialize.toBytes(key);

        checkSerializationFormat(serializedBytes, true, false);

        DiplomatiqAEAD unserialized = DiplomatiqAEAD.fromBytes(serializedBytes, key);

        Assertions.assertArrayEquals(plaintext, unserialized.getPlaintext());
        Assertions.assertArrayEquals(aad, unserialized.getAad());
    }

    @Test
    public void onlyEncryptedBig() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] plaintext = RandomUtils.bytes((int)Math.pow(2, 20));
        byte[] aad = new byte[0];

        byte[] key = RandomUtils.bytes(32);

        DiplomatiqAEAD toSerialize = new DiplomatiqAEAD(plaintext, aad);
        byte[] serializedBytes = toSerialize.toBytes(key);

        checkSerializationFormat(serializedBytes, true, false);

        DiplomatiqAEAD unserialized = DiplomatiqAEAD.fromBytes(serializedBytes, key);

        Assertions.assertArrayEquals(plaintext, unserialized.getPlaintext());
        Assertions.assertArrayEquals(aad, unserialized.getAad());
    }

    @Test
    public void onlyAuthenticated() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] plaintext = new byte[0];
        byte[] aad = RandomUtils.bytes(55);

        byte[] key = RandomUtils.bytes(32);

        DiplomatiqAEAD toSerialize = new DiplomatiqAEAD(plaintext, aad);
        byte[] serializedBytes = toSerialize.toBytes(key);

        checkSerializationFormat(serializedBytes, false, true);

        DiplomatiqAEAD unserialized = DiplomatiqAEAD.fromBytes(serializedBytes, key);

        Assertions.assertArrayEquals(plaintext, unserialized.getPlaintext());
        Assertions.assertArrayEquals(aad, unserialized.getAad());
    }

    @Test
    public void onlyAuthenticatedSmall() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] plaintext = new byte[0];
        byte[] aad = RandomUtils.bytes(1);

        byte[] key = RandomUtils.bytes(32);

        DiplomatiqAEAD toSerialize = new DiplomatiqAEAD(plaintext, aad);
        byte[] serializedBytes = toSerialize.toBytes(key);

        checkSerializationFormat(serializedBytes, false, true);

        DiplomatiqAEAD unserialized = DiplomatiqAEAD.fromBytes(serializedBytes, key);

        Assertions.assertArrayEquals(plaintext, unserialized.getPlaintext());
        Assertions.assertArrayEquals(aad, unserialized.getAad());
    }

    @Test
    public void onlyAuthenticatedBig() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] plaintext = new byte[0];
        byte[] aad = RandomUtils.bytes((int)Math.pow(2, 20));

        byte[] key = RandomUtils.bytes(32);

        DiplomatiqAEAD toSerialize = new DiplomatiqAEAD(plaintext, aad);
        byte[] serializedBytes = toSerialize.toBytes(key);

        checkSerializationFormat(serializedBytes, false, true);

        DiplomatiqAEAD unserialized = DiplomatiqAEAD.fromBytes(serializedBytes, key);

        Assertions.assertArrayEquals(plaintext, unserialized.getPlaintext());
        Assertions.assertArrayEquals(aad, unserialized.getAad());
    }

    @Test
    public void encryptedAndAuthenticated() throws NoSuchPaddingException, InvalidKeyException,
        NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] plaintext = RandomUtils.bytes(55);
        byte[] aad = RandomUtils.bytes(55);

        byte[] key = RandomUtils.bytes(32);

        DiplomatiqAEAD toSerialize = new DiplomatiqAEAD(plaintext, aad);
        byte[] serializedBytes = toSerialize.toBytes(key);

        checkSerializationFormat(serializedBytes, true, true);

        DiplomatiqAEAD unserialized = DiplomatiqAEAD.fromBytes(serializedBytes, key);

        Assertions.assertArrayEquals(plaintext, unserialized.getPlaintext());
        Assertions.assertArrayEquals(aad, unserialized.getAad());
    }

    @Test
    public void encryptedAndAuthenticatedSmall() throws NoSuchPaddingException, InvalidKeyException,
        NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] plaintext = RandomUtils.bytes(1);
        byte[] aad = RandomUtils.bytes(1);

        byte[] key = RandomUtils.bytes(32);

        DiplomatiqAEAD toSerialize = new DiplomatiqAEAD(plaintext, aad);
        byte[] serializedBytes = toSerialize.toBytes(key);

        checkSerializationFormat(serializedBytes, true, true);

        DiplomatiqAEAD unserialized = DiplomatiqAEAD.fromBytes(serializedBytes, key);

        Assertions.assertArrayEquals(plaintext, unserialized.getPlaintext());
        Assertions.assertArrayEquals(aad, unserialized.getAad());
    }

    @Test
    public void encryptedAndAuthenticatedBig() throws NoSuchPaddingException, InvalidKeyException,
        NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] plaintext = RandomUtils.bytes((int)Math.pow(2, 20));
        byte[] aad = RandomUtils.bytes((int)Math.pow(2, 20));

        byte[] key = RandomUtils.bytes(32);

        DiplomatiqAEAD toSerialize = new DiplomatiqAEAD(plaintext, aad);
        byte[] serializedBytes = toSerialize.toBytes(key);

        checkSerializationFormat(serializedBytes, true, true);

        DiplomatiqAEAD unserialized = DiplomatiqAEAD.fromBytes(serializedBytes, key);

        Assertions.assertArrayEquals(plaintext, unserialized.getPlaintext());
        Assertions.assertArrayEquals(aad, unserialized.getAad());
    }

    @Test
    public void empty() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] plaintext = new byte[0];
        byte[] aad = new byte[0];

        byte[] key = RandomUtils.bytes(32);

        DiplomatiqAEAD toSerialize = new DiplomatiqAEAD(plaintext, aad);
        byte[] serializedBytes = toSerialize.toBytes(key);

        checkSerializationFormat(serializedBytes, false, false);

        DiplomatiqAEAD unserialized = DiplomatiqAEAD.fromBytes(serializedBytes, key);

        Assertions.assertArrayEquals(plaintext, unserialized.getPlaintext());
        Assertions.assertArrayEquals(aad, unserialized.getAad());
    }

    @Test
    public void primaryConstructor() {
        byte[] plaintext = RandomUtils.bytes(30);
        DiplomatiqAEAD aead = new DiplomatiqAEAD(plaintext);
        Assertions.assertArrayEquals(plaintext, aead.getPlaintext());
        Assertions.assertArrayEquals(new byte[0], aead.getAad());
    }

    @Test
    public void primaryConstructorParameterNull() {
        DiplomatiqAEAD aead = new DiplomatiqAEAD(null);
        Assertions.assertArrayEquals(new byte[0], aead.getPlaintext());
        Assertions.assertArrayEquals(new byte[0], aead.getAad());
    }

    @Test
    public void constructorParametersNull() {
        DiplomatiqAEAD aead = new DiplomatiqAEAD(null, null);
        Assertions.assertArrayEquals(new byte[0], aead.getPlaintext());
        Assertions.assertArrayEquals(new byte[0], aead.getAad());
    }

    @Test
    public void invalidKeyLength() {
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new DiplomatiqAEAD(null, null).toBytes(RandomUtils.bytes(31)), "Key length must be 256 bits.");
    }
}
