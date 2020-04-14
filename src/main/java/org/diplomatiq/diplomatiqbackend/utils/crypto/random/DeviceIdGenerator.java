package org.diplomatiq.diplomatiqbackend.utils.crypto.random;

import java.security.NoSuchAlgorithmException;

public class DeviceIdGenerator {
    private static final int DEVICE_ID_LENGTH = 32;

    public static String generate() throws NoSuchAlgorithmException {
        return RandomUtils.alphanumericString(DEVICE_ID_LENGTH);
    }
}
