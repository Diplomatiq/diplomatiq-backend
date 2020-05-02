package org.diplomatiq.diplomatiqbackend.domain.entities.abstracts;

import org.diplomatiq.diplomatiqbackend.utils.crypto.random.EntityIdGenerator;
import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;

public abstract class AbstractIdentifiableNodeEntity {
    @Id
    @GeneratedValue(strategy = EntityIdGenerator.class)
    private String id;

    public final String getId() {
        return id;
    }

    public final void setId(String id) {
        this.id = id;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }

        if (!(other instanceof AbstractIdentifiableNodeEntity)) {
            return false;
        }

        AbstractIdentifiableNodeEntity otherAbstractIdentifiableNodeEntity = (AbstractIdentifiableNodeEntity)other;

        if (id == null || otherAbstractIdentifiableNodeEntity.getId() == null) {
            return false;
        }

        return id.equals(otherAbstractIdentifiableNodeEntity.getId());
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }
}
