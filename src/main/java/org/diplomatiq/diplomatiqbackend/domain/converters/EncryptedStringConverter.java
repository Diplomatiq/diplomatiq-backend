package org.diplomatiq.diplomatiqbackend.domain.converters;

import org.diplomatiq.diplomatiqbackend.exceptions.internal.GraphPropertyCryptoException;
import org.diplomatiq.diplomatiqbackend.utils.crypto.aead.DiplomatiqAEAD;
import org.neo4j.ogm.typeconversion.AttributeConverter;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class EncryptedStringConverter extends AbstractEncryptedConverter implements AttributeConverter<String, String> {
    @Override
    public String toGraphProperty(String s) {
        try {
            byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
            DiplomatiqAEAD diplomatiqAEAD = new DiplomatiqAEAD(bytes);
            byte[] encrypted = diplomatiqAEAD.toBytes(getEncryptionKey());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            throw new GraphPropertyCryptoException("Could not encrypt graph property.", ex);
        }
    }

    @Override
    public String toEntityAttribute(String s) {
        byte[] diplomatiqAeadBytes;
        try {
            diplomatiqAeadBytes = Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException ex) {
            throw new GraphPropertyCryptoException("Base64 could not be decoded.", ex);
        }

        for (byte[] keyCandidate : getDecryptionKeyCandidates()) {
            try {
                DiplomatiqAEAD diplomatiqAEAD = DiplomatiqAEAD.fromBytes(diplomatiqAeadBytes, keyCandidate);
                return new String(diplomatiqAEAD.getPlaintext(), StandardCharsets.UTF_8);
            } catch (Exception ignored) {}
        }

        throw new GraphPropertyCryptoException("Could not decrypt graph property.");
    }
}
