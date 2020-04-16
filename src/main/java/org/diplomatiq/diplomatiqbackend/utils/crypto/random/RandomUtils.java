package org.diplomatiq.diplomatiqbackend.utils.crypto.random;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RandomUtils {
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE = LOWERCASE.toUpperCase();
    private static final String ALPHABETIC = LOWERCASE + UPPERCASE;
    private static final String NUMERIC = "0123456789";
    private static final String ALPHANUMERIC = ALPHABETIC + NUMERIC;

    public static String lowercaseString(int length) {
        return generateSecureRandomString(LOWERCASE, length);
    }

    public static String uppercaseString(int length) {
        return generateSecureRandomString(UPPERCASE, length);
    }

    public static String alphabeticString(int length) {
        return generateSecureRandomString(ALPHABETIC, length);
    }

    public static String numericString(int length) {
        return generateSecureRandomString(NUMERIC, length);
    }

    public static String alphanumericString(int length) {
        return generateSecureRandomString(ALPHANUMERIC, length);
    }

    public static byte[] bytes(int count) {
        if (count <= 0) {
            throw new IllegalArgumentException("Cannot generate <= 0 secure random bytes.");
        }

        SecureRandom secureRandom = new SecureRandom();

        byte[] bytes = new byte[count];
        secureRandom.nextBytes(bytes);

        return bytes;
    }

    public static byte[] strongBytes(int count) {
        if (count <= 0) {
            throw new IllegalArgumentException("Cannot generate <= 0 secure random bytes.");
        }

        byte[] bytes = new byte[count];
        getStrongSecureRandom().nextBytes(bytes);

        return bytes;
    }

    public static SecureRandom getStrongSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no strong SecureRandom available");
        }
    }

    private static String generateSecureRandomString(String alphabet, int length) {
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
}
