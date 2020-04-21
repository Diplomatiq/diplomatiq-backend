package org.diplomatiq.diplomatiqbackend.utils.crypto.aead;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * AEAD (Authenticated Encryption with Associated Data) structure with binary serialization and deserialization
 * features.
 * <p>
 * Serialization scheme:
 * HEADER:
 * - 1 byte                     ivLength = initialization vector length in bytes
 * - 4 bytes                    aadLength = additional authenticated data length in bytes, big-endian
 * - 4 bytes                    ciphertextLength = ciphertext length in bytes, big-endian
 * - 1 byte                     tagLength = authentication tag length in bytes
 * BODY:
 * - ivLength bytes             the initialization vector
 * - aadLength bytes            the additional authenticated data
 * - ciphertextLength bytes     the ciphertext
 * - tagLength bytes            the authentication tag
 */
public class DiplomatiqAEAD {
    private static final int INITIALIZATION_VECTOR_LENGTH_BYTES = 12;
    private static final int AUTHENTICATION_TAG_LENGTH_BYTES = 16;
    private static final String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
    private static final String AES = "AES";

    private final byte[] plaintext;
    private final byte[] aad;

    public DiplomatiqAEAD(byte[] plaintext) {
        this.plaintext = plaintext != null ? plaintext : new byte[0];
        aad = new byte[0];
    }

    public DiplomatiqAEAD(byte[] plaintext, byte[] aad) {
        this.plaintext = plaintext != null ? plaintext : new byte[0];
        this.aad = aad != null ? aad : new byte[0];
    }

    public byte[] getPlaintext() {
        return plaintext;
    }

    public byte[] getAad() {
        return aad;
    }

    public byte[] toBytes(byte[] key) throws NoSuchPaddingException,
        NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
        IllegalBlockSizeException, IOException {
        if (key.length != 32) {
            throw new IllegalArgumentException("Key length must be 256 bits.");
        }

        Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES);

        byte[] initializationVector = new byte[INITIALIZATION_VECTOR_LENGTH_BYTES];
        SecureRandom strongRandom = SecureRandom.getInstanceStrong();
        strongRandom.nextBytes(initializationVector);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AUTHENTICATION_TAG_LENGTH_BYTES * 8,
            initializationVector);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        if (aad.length > 0) {
            cipher.updateAAD(aad);
        }

        byte[] ciphertextWithAuthenticationTag = cipher.doFinal(plaintext);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        byteArrayOutputStream.write(INITIALIZATION_VECTOR_LENGTH_BYTES);

        byte[] aadLengthBytes = ByteBuffer.allocate(4).putInt(aad.length).array();
        byteArrayOutputStream.write(aadLengthBytes);

        byte[] ciphertextLengthBytes = ByteBuffer.allocate(4).putInt(plaintext.length).array();
        byteArrayOutputStream.write(ciphertextLengthBytes);

        byteArrayOutputStream.write(AUTHENTICATION_TAG_LENGTH_BYTES);
        byteArrayOutputStream.write(initializationVector);

        if (aad.length > 0) {
            byteArrayOutputStream.write(aad);
        }

        byteArrayOutputStream.write(ciphertextWithAuthenticationTag);

        return byteArrayOutputStream.toByteArray();
    }

    public static DiplomatiqAEAD fromBytes(byte[] diplomatiqAEAD, byte[] key) throws IOException,
        NoSuchPaddingException,
        NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
        IllegalBlockSizeException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(diplomatiqAEAD);

        int initializationVectorLength = byteArrayInputStream.read();
        int aadLength = ByteBuffer.wrap(byteArrayInputStream.readNBytes(4)).getInt();
        int ciphertextLength = ByteBuffer.wrap(byteArrayInputStream.readNBytes(4)).getInt();
        int authenticationTagLength = byteArrayInputStream.read();

        byte[] initializationVector = byteArrayInputStream.readNBytes(initializationVectorLength);
        byte[] authenticated = aadLength > 0 ? byteArrayInputStream.readNBytes(aadLength) : new byte[0];
        byte[] ciphertextWithAuthenticationTag =
            byteArrayInputStream.readNBytes(ciphertextLength + authenticationTagLength);

        Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES);

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AUTHENTICATION_TAG_LENGTH_BYTES * 8,
            initializationVector);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        if (authenticated.length > 0) {
            cipher.updateAAD(authenticated);
        }

        byte[] encrypted = cipher.doFinal(ciphertextWithAuthenticationTag);

        return new DiplomatiqAEAD(encrypted, authenticated);
    }
}
