package org.diplomatiq.diplomatiqbackend.filters.authentication;

import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqAuthenticationScheme;

public class AuthenticationDetails {
    private final DiplomatiqAuthenticationScheme authenticationScheme;
    private final String authenticationId;

    public AuthenticationDetails(DiplomatiqAuthenticationScheme authenticationScheme, String authenticationId) {
        this.authenticationScheme = authenticationScheme;
        this.authenticationId = authenticationId;
    }

    public DiplomatiqAuthenticationScheme diplomatiqAuthenticationScheme() {
        return authenticationScheme;
    }

    public String getAuthenticationId() {
        return authenticationId;
    }
}
