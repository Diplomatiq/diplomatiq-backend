package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.AuthenticationSession;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class AuthenticationSessionHelper {
    private static final Duration AUTHENTICATION_SESSION_VALIDITY = Duration.ofMinutes(10);

    public static AuthenticationSession createAuthenticationSessionWithKey(byte[] authenticationSessionKey) {
        AuthenticationSession authenticationSession = new AuthenticationSession();

        authenticationSession.setExpirationTimeDelta(AUTHENTICATION_SESSION_VALIDITY);
        authenticationSession.setAuthenticationSessionKey(authenticationSessionKey);

        return authenticationSession;
    }
}
