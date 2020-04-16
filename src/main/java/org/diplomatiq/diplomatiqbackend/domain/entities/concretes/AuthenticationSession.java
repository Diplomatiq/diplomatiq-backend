package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

@NodeEntity
public class AuthenticationSession extends AbstractExpiringNodeEntity {
    private byte[] authenticationSessionKey;

    @Relationship(type = "HAS_AUTHENTICATION_SESSION", direction = Relationship.INCOMING)
    private UserAuthentication userAuthentication;

    public byte[] getAuthenticationSessionKey() {
        return authenticationSessionKey;
    }

    public void setAuthenticationSessionKey(byte[] authenticationSessionKey) {
        this.authenticationSessionKey = authenticationSessionKey;
    }

    public UserAuthentication getUserAuthentication() {
        return userAuthentication;
    }

    public void setUserAuthentication(UserAuthentication userAuthentication) {
        this.userAuthentication = userAuthentication;
    }
}
