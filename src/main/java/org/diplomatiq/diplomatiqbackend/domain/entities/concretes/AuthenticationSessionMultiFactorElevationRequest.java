package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;
import org.neo4j.ogm.annotation.Relationship;

public class AuthenticationSessionMultiFactorElevationRequest extends AbstractExpiringNodeEntity {
    private String requestCode;

    @Relationship(type = "HAS_ELEVATION_REQUEST", direction = Relationship.INCOMING)
    private AuthenticationSession authenticationSession;

    public String getRequestCode() {
        return requestCode;
    }

    public void setRequestCode(String requestCode) {
        this.requestCode = requestCode;
    }

    public AuthenticationSession getAuthenticationSession() {
        return authenticationSession;
    }

    public void setAuthenticationSession(AuthenticationSession authenticationSession) {
        this.authenticationSession = authenticationSession;
    }
}
