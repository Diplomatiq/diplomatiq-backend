package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;

import java.time.Duration;
import java.time.Instant;

public class ExpirationHelper {
    public static boolean isExpiredNow(AbstractExpiringNodeEntity entity) {
        return isExpiredAt(entity, Instant.now());
    }

    public static boolean isExpiredIn(AbstractExpiringNodeEntity entity, Duration in) {
        return isExpiredAt(entity, Instant.now().plus(in));
    }

    public static boolean isExpiredAt(AbstractExpiringNodeEntity entity, Instant at) {
        return entity.getExpirationTime().isBefore(at);
    }
}
