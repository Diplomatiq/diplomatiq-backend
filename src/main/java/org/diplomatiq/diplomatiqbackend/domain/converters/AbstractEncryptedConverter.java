package org.diplomatiq.diplomatiqbackend.domain.converters;

import java.util.*;

public abstract class AbstractEncryptedConverter {
    protected NavigableMap<Integer, byte[]> getKeyByVersionMap() {
        NavigableMap<Integer, byte[]> keyByVersionMap = new TreeMap<>();
        keyByVersionMap.put(1, getKeyFromEnvironmentVariableOrGetDummyKey("NEO4J_ENCRYPTION_KEY_V1"));
        return Collections.unmodifiableNavigableMap(keyByVersionMap);
    }

    protected byte[] getLatestKey() {
        NavigableMap<Integer, byte[]> keyByVersionMap = getKeyByVersionMap();
        return keyByVersionMap.get(Collections.max(keyByVersionMap.keySet()));
    }

    private byte[] getKeyFromEnvironmentVariableOrGetDummyKey(String environmentVariableName) {
        return Base64.getDecoder().decode(Optional.ofNullable(System.getenv(environmentVariableName)).orElseThrow());
    }
}
