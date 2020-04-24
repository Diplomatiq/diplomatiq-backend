package org.diplomatiq.diplomatiqbackend.domain.entities.abstracts;

import java.time.Instant;

public abstract class AbstractExpiringNodeEntity extends AbstractCreationRecordedNodeEntity {
    private Instant expirationTime;

    public Instant getExpirationTime() {
        return expirationTime;
    }

    public void setExpirationTime(Instant expirationTime) {
        this.expirationTime = expirationTime;
    }
}
