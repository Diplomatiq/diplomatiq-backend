package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.Session;
import org.diplomatiq.diplomatiqbackend.methods.descriptors.SessionLevelOfAssurance;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.stream.Stream;

@Component
public class SessionHelper {
    private static final Duration SESSION_VALIDITY = Duration.ofHours(1);
    private static final Duration PASSWORD_ELEVATED_LEVEL_VALIDITY = Duration.ofMinutes(10);
    private static final Duration MULTI_FACTOR_ELEVATED_LEVEL_VALIDITY = Duration.ofMinutes(5);

    public static Session createSession() {
        Session session = new Session();
        session.setExpirationTimeDelta(SESSION_VALIDITY);
        session.setLevelOfAssurance(SessionLevelOfAssurance.RegularSession);
        session.setLevelOfAssuranceExpirationTime(session.getExpirationTime());
        return session;
    }

    public static Session elevateSessionToPasswordElevated(Session session) {
        session.setLevelOfAssurance(SessionLevelOfAssurance.PasswordElevatedSession);

        Instant loaMaxExpirationTime = Instant.now().plus(PASSWORD_ELEVATED_LEVEL_VALIDITY);
        Instant sessionExpirationTime = session.getExpirationTime();

        Instant loaExpirationTime =
            Stream.of(loaMaxExpirationTime, sessionExpirationTime).min(Instant::compareTo).get();
        session.setLevelOfAssuranceExpirationTime(loaExpirationTime);

        return session;
    }

    public static Session elevateSessionToMultiFactorElevated(Session session) {
        session.setLevelOfAssurance(SessionLevelOfAssurance.MultiFactorElevatedSession);

        Instant loaMaxExpirationTime = Instant.now().plus(MULTI_FACTOR_ELEVATED_LEVEL_VALIDITY);
        Instant sessionExpirationTime = session.getExpirationTime();

        Instant loaExpirationTime =
            Stream.of(loaMaxExpirationTime, sessionExpirationTime).min(Instant::compareTo).get();
        session.setLevelOfAssuranceExpirationTime(loaExpirationTime);

        return session;
    }
}
