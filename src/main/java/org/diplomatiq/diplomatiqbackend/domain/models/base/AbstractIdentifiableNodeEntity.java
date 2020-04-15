package org.diplomatiq.diplomatiqbackend.domain.models.base;

import org.neo4j.ogm.annotation.Index;

public abstract class AbstractIdentifiableNodeEntity extends AbstractNodeEntity {
    @Index(unique = true)
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

        if (id == null || otherAbstractIdentifiableNodeEntity.id == null) {
            return false;
        }

        return id.equals(otherAbstractIdentifiableNodeEntity.id);
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }
}
