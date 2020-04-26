package org.diplomatiq.diplomatiqbackend.domain.entities.utils;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;

import java.time.Duration;
import java.time.Instant;

public class ExpirationUtils {
    public static boolean isExpiredNow(AbstractExpiringNodeEntity entity) {
        return isExpiredAt(entity, Instant.now());
    }

    public static boolean isExpiredNow(Instant instant) {
        return isExpiredAt(instant, Instant.now());
    }

    public static boolean isExpiredIn(AbstractExpiringNodeEntity entity, Duration in) {
        return isExpiredAt(entity, Instant.now().plus(in));
    }

    public static boolean isExpiredIn(Instant instant, Duration in) {
        return isExpiredAt(instant, Instant.now().plus(in));
    }

    public static boolean isExpiredAt(AbstractExpiringNodeEntity entity, Instant at) {
        return entity.getExpirationTime().isBefore(at);
    }

    public static boolean isExpiredAt(Instant instant, Instant at) {
        return instant.isBefore(at);
    }

    public static void setExpirationLifeSpan(AbstractExpiringNodeEntity entity, Duration duration) {
        entity.setExpirationTime(entity.getCreationTime().plus(duration));
    }

    public static void setExpirationTimeDelta(AbstractExpiringNodeEntity entity, Duration duration) {
        entity.setExpirationTime(Instant.now().plus(duration));
    }
}
