package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;

import java.time.Instant;

public class ExpirationHelper {
    public static boolean isExpired(AbstractExpiringNodeEntity entity) {
        return isExpired(entity, Instant.now());
    }

    public static boolean isExpired(AbstractExpiringNodeEntity entity, Instant at) {
        return entity.getExpirationTime().isBefore(at);
    }
}
