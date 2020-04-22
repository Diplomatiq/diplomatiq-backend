package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.Session;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class SessionHelper {
    private static final Duration SESSION_VALIDITY = Duration.ofHours(1);

    public static Session createSession() {
        Session session = new Session();
        session.setExpirationTimeDelta(SESSION_VALIDITY);
        return session;
    }
}
