package org.diplomatiq.diplomatiqbackend.utils.crypto.random;

public class SessionTokenGenerator {
    private static final int SESSION_TOKEN_LENGTH = 32;

    public static byte[] generate() {
        return RandomUtils.strongBytes(SESSION_TOKEN_LENGTH);
    }
}
