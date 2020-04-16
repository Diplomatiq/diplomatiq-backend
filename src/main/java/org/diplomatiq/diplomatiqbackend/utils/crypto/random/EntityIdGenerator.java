package org.diplomatiq.diplomatiqbackend.utils.crypto.random;

import org.neo4j.ogm.id.IdStrategy;

public class EntityIdGenerator implements IdStrategy {
    private static final int ENTITY_ID_LENGTH = 32;

    @Override
    public Object generateId(Object o) {
        return RandomUtils.alphanumericString(ENTITY_ID_LENGTH);
    }
}
