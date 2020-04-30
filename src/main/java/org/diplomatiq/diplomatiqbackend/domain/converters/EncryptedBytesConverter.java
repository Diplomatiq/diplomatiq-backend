package org.diplomatiq.diplomatiqbackend.domain.converters;

import org.diplomatiq.diplomatiqbackend.exceptions.internal.GraphPropertyCryptoException;
import org.diplomatiq.diplomatiqbackend.utils.crypto.aead.DiplomatiqAEAD;
import org.neo4j.ogm.typeconversion.AttributeConverter;

import java.util.Base64;

public class EncryptedBytesConverter extends AbstractEncryptedConverter implements AttributeConverter<byte[], String> {
    @Override
    public String toGraphProperty(byte[] bytes) {
        try {
            DiplomatiqAEAD diplomatiqAEAD = new DiplomatiqAEAD(bytes);
            byte[] encrypted = diplomatiqAEAD.toBytes(getEncryptionKey());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            throw new GraphPropertyCryptoException("Could not encrypt graph property.", ex);
        }
    }

    @Override
    public byte[] toEntityAttribute(String s) {
        byte[] diplomatiqAeadBytes;
        try {
             diplomatiqAeadBytes = Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException ex) {
            throw new GraphPropertyCryptoException("Base64 could not be decoded.", ex);
        }

        for (byte[] keyCandidate : getDecryptionKeyCandidates()) {
            try {
                DiplomatiqAEAD diplomatiqAEAD = DiplomatiqAEAD.fromBytes(diplomatiqAeadBytes, keyCandidate);
                return diplomatiqAEAD.getPlaintext();
            } catch (Exception ignored) {}
        }

        throw new GraphPropertyCryptoException("Could not decrypt graph property.");
    }
}
