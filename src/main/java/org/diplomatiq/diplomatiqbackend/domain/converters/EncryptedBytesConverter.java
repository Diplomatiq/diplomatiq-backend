package org.diplomatiq.diplomatiqbackend.domain.converters;

import org.diplomatiq.diplomatiqbackend.exceptions.internal.GraphPropertyCryptoException;
import org.diplomatiq.diplomatiqbackend.utils.crypto.aead.DiplomatiqAEAD;
import org.neo4j.ogm.typeconversion.AttributeConverter;

import java.util.*;

public class EncryptedBytesConverter implements AttributeConverter<byte[], String> {
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
            for (byte[] keyCandidate : getKeyByVersionMap().descendingMap().values()) {
                DiplomatiqAEAD diplomatiqAEAD = DiplomatiqAEAD.fromBytes(diplomatiqAEADBytes, keyCandidate);
                return diplomatiqAEAD.getPlaintext();
            }
        } catch (Throwable ex) {
            throw new GraphPropertyCryptoException("Could not decrypt graph property.", ex);
        }

        throw new GraphPropertyCryptoException("Could not decrypt graph property.");
    }

    private NavigableMap<Integer, byte[]> getKeyByVersionMap() {
        NavigableMap<Integer, byte[]> keyByVersionMap = new TreeMap<>();
        keyByVersionMap.put(1, getKeyFromEnvironmentVariableOrGetDummyKey("NEO4J_ENCRYPTION_KEY_V1"));
        return Collections.unmodifiableNavigableMap(keyByVersionMap);
    }

    private byte[] getLatestKey() {
        NavigableMap<Integer, byte[]> keyByVersionMap = getKeyByVersionMap();
        return keyByVersionMap.get(Collections.max(keyByVersionMap.keySet()));
    }

    private byte[] getKeyFromEnvironmentVariableOrGetDummyKey(String environmentVariableName) {
        return Base64.getDecoder().decode(Optional.ofNullable(System.getenv(environmentVariableName)).orElseThrow());
    }
}
