package org.diplomatiq.diplomatiqbackend.domain.converters;

import org.diplomatiq.diplomatiqbackend.exceptions.internal.GraphPropertyCryptoException;
import org.diplomatiq.diplomatiqbackend.utils.crypto.aead.DiplomatiqAEAD;
import org.neo4j.ogm.typeconversion.AttributeConverter;

import java.util.*;

public class EncryptedBytesConverter implements AttributeConverter<byte[], String> {
    private static final String DUMMY_ENCRYPTION_KEY_BASE64 = "c2VjcmV0c2VjcmV0IHNlY3JldCBzZWNyZXRzZWNyZXQ=";

    private final NavigableMap<Integer, byte[]> keyByVersionMap;

    EncryptedBytesConverter() {
        NavigableMap<Integer, byte[]> keyByVersionMap = new TreeMap<>();
        keyByVersionMap.put(1, getKeyFromEnvironmentVariableOrGetDummyKey("NEO4J_ENCRYPTION_KEY_V1"));

        this.keyByVersionMap = Collections.unmodifiableNavigableMap(keyByVersionMap);
    }

    @Override
    public String toGraphProperty(byte[] bytes) {
        try {
            DiplomatiqAEAD diplomatiqAEAD = new DiplomatiqAEAD(bytes);
            byte[] encrypted = diplomatiqAEAD.toBytes(getLatestKey());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            throw new GraphPropertyCryptoException("Could not encrypt graph property.", ex);
        }
    }

    @Override
    public byte[] toEntityAttribute(String s) {
        try {
            byte[] diplomatiqAEADBytes = Base64.getDecoder().decode(s);
            for (byte[] keyCandidate : keyByVersionMap.descendingMap().values()) {
                DiplomatiqAEAD diplomatiqAEAD = DiplomatiqAEAD.fromBytes(diplomatiqAEADBytes, keyCandidate);
                return diplomatiqAEAD.getPlaintext();
            }
        } catch (Throwable ex) {
            // ignored
        }

        throw new GraphPropertyCryptoException("Could not decrypt graph property.");
    }

    private byte[] getLatestKey() {
        return keyByVersionMap.get(Collections.max(keyByVersionMap.keySet()));
    }

    private byte[] getKeyFromEnvironmentVariableOrGetDummyKey(String environmentVariableName) {
        return Base64.getDecoder().decode(
            Optional.ofNullable(System.getenv(environmentVariableName))
                .orElse(DUMMY_ENCRYPTION_KEY_BASE64)
        );
    }
}
