package org.diplomatiq.diplomatiqbackend.utils.crypto.random;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RandomUtils {
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE = LOWERCASE.toUpperCase();
    private static final String ALPHABETIC = LOWERCASE + UPPERCASE;
    private static final String NUMERIC = "0123456789";
    private static final String ALPHANUMERIC = ALPHABETIC + NUMERIC;

    private static String generateSecureRandomString(String alphabet, int length) throws NoSuchAlgorithmException {
        if (alphabet.equals("")) {
            throw new IllegalArgumentException("Cannot generate secure random from empty alphabet.");
        }

        if (length <= 0) {
            throw new IllegalArgumentException("Cannot generate secure random string with <= 0 length.");
        }

        SecureRandom secureRandom = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < length; i++) {
            int random = secureRandom.nextInt(alphabet.length());
            char randomCharacter = alphabet.charAt(random);
            stringBuilder.append(randomCharacter);
        }

        return stringBuilder.toString();
    }

    public static String lowercaseString(int length) throws NoSuchAlgorithmException {
        return generateSecureRandomString(LOWERCASE, length);
    }

    public static String uppercaseString(int length) throws NoSuchAlgorithmException {
        return generateSecureRandomString(UPPERCASE, length);
    }

    public static String alphabeticString(int length) throws NoSuchAlgorithmException {
        return generateSecureRandomString(ALPHABETIC, length);
    }

    public static String numericString(int length) throws NoSuchAlgorithmException {
        return generateSecureRandomString(NUMERIC, length);
    }

    public static String alphanumericString(int length) throws NoSuchAlgorithmException {
        return generateSecureRandomString(ALPHANUMERIC, length);
    }

    public static byte[] bytes(int count) throws NoSuchAlgorithmException {
        if (count <= 0) {
            throw new IllegalArgumentException("Cannot generate <= 0 secure random bytes.");
        }

        SecureRandom secureRandom = new SecureRandom();

        byte[] bytes = new byte[count];
        secureRandom.nextBytes(bytes);

        return bytes;
    }

    public static byte[] strongBytes(int count) throws NoSuchAlgorithmException {
        if (count <= 0) {
            throw new IllegalArgumentException("Cannot generate <= 0 secure random bytes.");
        }

        SecureRandom secureRandom = SecureRandom.getInstanceStrong();

        byte[] bytes = new byte[count];
        secureRandom.nextBytes(bytes);

        return bytes;
    }
}
