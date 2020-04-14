package org.diplomatiq.diplomatiqbackend.utils.crypto.random;

import java.security.NoSuchAlgorithmException;

public class AuthenticationSessionIdGenerator {
    private static final int AUTHENTICATION_SESSION_ID_LENGTH = 32;

    public static String generate() throws NoSuchAlgorithmException {
        return RandomUtils.alphanumericString(AUTHENTICATION_SESSION_ID_LENGTH);
    }
}
