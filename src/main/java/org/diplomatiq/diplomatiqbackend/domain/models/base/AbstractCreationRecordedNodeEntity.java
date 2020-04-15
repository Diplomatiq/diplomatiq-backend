package org.diplomatiq.diplomatiqbackend.domain.models.base;

import java.time.Instant;

public abstract class AbstractCreationRecordedNodeEntity extends AbstractIdentifiableNodeEntity {
    Instant creationTime;

    public AbstractCreationRecordedNodeEntity() {
        creationTime = Instant.now();
    }

    public Instant getCreationTime() {
        return creationTime;
    }
}
