package org.diplomatiq.diplomatiqbackend.domain.converters;

import org.neo4j.ogm.typeconversion.AttributeConverter;

public class BytesEncryptedConverter implements AttributeConverter<byte[], String> {
    @Override
    public String toGraphProperty(byte[] bytes) {
        return null;
    }

    @Override
    public byte[] toEntityAttribute(String s) {
        return new byte[0];
    }
}
