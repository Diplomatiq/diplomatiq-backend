package org.diplomatiq.diplomatiqbackend.domain.models.base;

import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;

public abstract class AbstractNodeEntity {
    @Id
    @GeneratedValue
    private Long id;

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }

        if (!(other instanceof AbstractNodeEntity)) {
            return false;
        }

        AbstractNodeEntity otherAbstractNodeEntity = (AbstractNodeEntity)other;

        if (id == null || otherAbstractNodeEntity.id == null) {
            return false;
        }

        return id.equals(otherAbstractNodeEntity.id);
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }
}
