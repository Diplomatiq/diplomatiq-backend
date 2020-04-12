package org.diplomatiq.diplomatiqbackend.filters.authentication;

import org.diplomatiq.diplomatiqbackend.entities.UserIdentity;
import org.springframework.security.authentication.AbstractAuthenticationToken;

public class SessionAuthenticationToken extends AbstractAuthenticationToken {
    private final UserIdentity userIdentity;
    private final String sessionId;

    public SessionAuthenticationToken(UserIdentity userIdentity, String sessionId) {
        super(null);
        this.userIdentity = userIdentity;
        this.sessionId = sessionId;
        setAuthenticated(true);
    }

    @Override
    public UserIdentity getPrincipal() {
        return userIdentity;
    }

    @Override
    public String getCredentials() {
        return sessionId;
    }
}
