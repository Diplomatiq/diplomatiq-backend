package org.diplomatiq.diplomatiqbackend.domain.converters;

import java.util.*;

public abstract class AbstractEncryptedConverter {
    protected byte[] getEncryptionKey() {
        NavigableMap<Integer, byte[]> keyByVersionMap = getKeyByVersionMap();
        return keyByVersionMap.get(Collections.max(keyByVersionMap.keySet()));
    }

    protected Iterable<byte[]> getDecryptionKeyCandidates() {
        NavigableMap<Integer, byte[]> keyByVersionMap = getKeyByVersionMap();
        return keyByVersionMap.descendingMap().values();
    }

    private NavigableMap<Integer, byte[]> getKeyByVersionMap() {
        NavigableMap<Integer, byte[]> keyByVersionMap = new TreeMap<>();
        keyByVersionMap.put(1, getKeyFromEnvironmentVariable("NEO4J_ENCRYPTION_KEY_V1"));
        return Collections.unmodifiableNavigableMap(keyByVersionMap);
    }

    private byte[] getKeyFromEnvironmentVariable(String environmentVariableName) {
        return Base64.getDecoder().decode(Optional.ofNullable(System.getenv(environmentVariableName)).orElseThrow());
    }
}
