package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.AuthenticationSession;
import org.diplomatiq.diplomatiqbackend.domain.entities.utils.ExpirationUtils;
import org.diplomatiq.diplomatiqbackend.methods.attributes.SessionAssuranceLevel;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.stream.Stream;

@Component
public class AuthenticationSessionHelper {
    private static final Duration AUTHENTICATION_SESSION_VALIDITY = Duration.ofMinutes(10);
    private static final Duration MULTI_FACTOR_ELEVATED_LEVEL_VALIDITY = Duration.ofMinutes(5);

    public static AuthenticationSession create(byte[] authenticationSessionKey) {
        AuthenticationSession authenticationSession = new AuthenticationSession();
        ExpirationUtils.setExpirationLifeSpan(authenticationSession, AUTHENTICATION_SESSION_VALIDITY);
        authenticationSession.setAuthenticationSessionKey(authenticationSessionKey);
        return authenticationSession;
    }

    public static void elevateAuthenticationSessionToMultiFactorElevated(AuthenticationSession authenticationSession) {
        authenticationSession.setAssuranceLevel(SessionAssuranceLevel.MultiFactorElevatedSession);

        Instant loaMaxExpirationTime = Instant.now().plus(MULTI_FACTOR_ELEVATED_LEVEL_VALIDITY);
        Instant authenticationSessionExpirationTime = authenticationSession.getExpirationTime();

        Instant loaExpirationTime =
            Stream.of(loaMaxExpirationTime, authenticationSessionExpirationTime).min(Instant::compareTo).get();
        authenticationSession.setAssuranceLevelExpirationTime(loaExpirationTime);
    }

    public static void downgradeAuthenticationSessionToPasswordElevated(AuthenticationSession authenticationSession) {
        authenticationSession.setAssuranceLevel(SessionAssuranceLevel.MultiFactorElevatedSession);
        authenticationSession.setAssuranceLevelExpirationTime(authenticationSession.getExpirationTime());
    }
}
