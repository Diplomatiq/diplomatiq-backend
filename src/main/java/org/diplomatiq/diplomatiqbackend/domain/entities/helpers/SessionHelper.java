package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.Session;
import org.diplomatiq.diplomatiqbackend.domain.entities.utils.ExpirationUtils;
import org.diplomatiq.diplomatiqbackend.methods.attributes.SessionAssuranceLevel;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.stream.Stream;

@Component
public class SessionHelper {
    private static final Duration SESSION_VALIDITY = Duration.ofHours(1);
    private static final Duration PASSWORD_ELEVATED_LEVEL_VALIDITY = Duration.ofMinutes(10);
    private static final Duration MULTI_FACTOR_ELEVATED_LEVEL_VALIDITY = Duration.ofMinutes(5);

    public static Session create() {
        Session session = new Session();
        ExpirationUtils.setExpirationLifeSpan(session, SESSION_VALIDITY);
        session.setAssuranceLevel(SessionAssuranceLevel.RegularSession);
        session.setAssuranceLevelExpirationTime(session.getExpirationTime());
        return session;
    }

    public static void elevateSessionToPasswordElevated(Session session) {
        session.setAssuranceLevel(SessionAssuranceLevel.PasswordElevatedSession);

        Instant loaMaxExpirationTime = Instant.now().plus(PASSWORD_ELEVATED_LEVEL_VALIDITY);
        Instant sessionExpirationTime = session.getExpirationTime();

        Instant loaExpirationTime =
            Stream.of(loaMaxExpirationTime, sessionExpirationTime).min(Instant::compareTo).get();
        session.setAssuranceLevelExpirationTime(loaExpirationTime);
    }

    public static void elevateSessionToMultiFactorElevated(Session session) {
        session.setAssuranceLevel(SessionAssuranceLevel.MultiFactorElevatedSession);

        Instant loaMaxExpirationTime = Instant.now().plus(MULTI_FACTOR_ELEVATED_LEVEL_VALIDITY);
        Instant sessionExpirationTime = session.getExpirationTime();

        Instant loaExpirationTime =
            Stream.of(loaMaxExpirationTime, sessionExpirationTime).min(Instant::compareTo).get();
        session.setAssuranceLevelExpirationTime(loaExpirationTime);
    }

    public static void downgradeSessionToRegular(Session session) {
        session.setAssuranceLevel(SessionAssuranceLevel.RegularSession);
        session.setAssuranceLevelExpirationTime(session.getExpirationTime());
    }
}
