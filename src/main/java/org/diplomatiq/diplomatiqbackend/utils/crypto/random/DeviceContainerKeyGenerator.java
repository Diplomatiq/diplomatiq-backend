package org.diplomatiq.diplomatiqbackend.utils.crypto.random;

public class DeviceContainerKeyGenerator {
    private static final int DEVICE_CONTAINER_KEY_LENGTH = 32;

    public static byte[] generate() {
        return RandomUtils.strongBytes(DEVICE_CONTAINER_KEY_LENGTH);
    }
}
