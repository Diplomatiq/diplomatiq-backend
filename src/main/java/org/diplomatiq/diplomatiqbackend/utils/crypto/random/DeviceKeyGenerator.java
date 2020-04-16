package org.diplomatiq.diplomatiqbackend.utils.crypto.random;

public class DeviceKeyGenerator {
    private static final int DEVICE_KEY_LENGTH = 32;

    public static byte[] generate() {
        return RandomUtils.strongBytes(DEVICE_KEY_LENGTH);
    }
}
