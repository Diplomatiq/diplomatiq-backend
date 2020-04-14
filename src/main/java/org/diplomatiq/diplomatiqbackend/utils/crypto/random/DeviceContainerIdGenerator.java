package org.diplomatiq.diplomatiqbackend.utils.crypto.random;

import java.security.NoSuchAlgorithmException;

public class DeviceContainerIdGenerator {
    private static final int DEVICE_CONTAINER_ID_LENGTH = 32;

    public static String generate() throws NoSuchAlgorithmException {
        return RandomUtils.alphanumericString(DEVICE_CONTAINER_ID_LENGTH);
    }
}
