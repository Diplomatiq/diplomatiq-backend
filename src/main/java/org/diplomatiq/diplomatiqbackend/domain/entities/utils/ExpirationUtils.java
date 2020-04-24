package org.diplomatiq.diplomatiqbackend.domain.entities.utils;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;

import java.time.Duration;
import java.time.Instant;

public class ExpirationUtils {
    public static boolean isExpiredNow(AbstractExpiringNodeEntity entity) {
        return isExpiredAt(entity, Instant.now());
    }

    public static boolean isExpiredIn(AbstractExpiringNodeEntity entity, Duration duration) {
        return isExpiredAt(entity, Instant.now().plus(duration));
    }

    public static boolean isExpiredAt(AbstractExpiringNodeEntity entity, Instant instant) {
        return entity.getExpirationTime().isBefore(instant);
    }

    public static void setExpirationLifeSpan(AbstractExpiringNodeEntity entity, Duration duration) {
        entity.setExpirationTime(entity.getCreationTime().plus(duration));
    }

    public static void setExpirationTimeDelta(AbstractExpiringNodeEntity entity, Duration duration) {
        entity.setExpirationTime(Instant.now().plus(duration));
    }
}
