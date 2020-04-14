package org.diplomatiq.diplomatiqbackend.utils.crypto.random;

import java.security.NoSuchAlgorithmException;

public class DeviceKeyGenerator {
    private static final int DEVICE_KEY_LENGTH = 32;

    public static byte[] generate() throws NoSuchAlgorithmException {
        return RandomUtils.strongBytes(DEVICE_KEY_LENGTH);
    }
}
