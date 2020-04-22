package org.diplomatiq.diplomatiqbackend.filters.authentication;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.springframework.security.authentication.AbstractAuthenticationToken;

public class AuthenticationToken extends AbstractAuthenticationToken {
    private final UserIdentity userIdentity;
    private final AuthenticationDetails authenticationDetails;

    public AuthenticationToken(UserIdentity userIdentity, AuthenticationDetails authenticationDetails) {
        super(null);
        this.userIdentity = userIdentity;
        this.authenticationDetails = authenticationDetails;
        setAuthenticated(true);
    }

    @Override
    public UserIdentity getPrincipal() {
        return userIdentity;
    }

    @Override
    public AuthenticationDetails getCredentials() {
        return authenticationDetails;
    }
}
