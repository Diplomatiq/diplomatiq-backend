package org.diplomatiq.diplomatiqbackend.domain.models.base;

import java.time.Duration;
import java.time.Instant;

public abstract class AbstractExpiringNodeEntity extends AbstractCreationRecordedNodeEntity {
    private Instant expirationTime;

    public Instant getExpirationTime() {
        return expirationTime;
    }

    public void setExpirationTime(Instant expirationTime) {
        this.expirationTime = expirationTime;
    }

    public void setExpirationTimeDelta(Duration duration) {
        expirationTime = expirationTime.plus(duration);
    }
}
