package org.diplomatiq.diplomatiqbackend.domain.models;

import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.Index;
import org.neo4j.ogm.annotation.Relationship;

public class AuthenticationSession {
    @Id
    @GeneratedValue
    private Long id;

    @Index(unique = true)
    private String authenticationSessionId;

    private byte[] authenticationSessionKey;

    @Relationship(type = "IS_CURRENTLY_LOGGING_IN_WITH_AUTHENTICATION_SESSION", direction = Relationship.INCOMING)
    private UserAuthentication userAuthentication;

    public String getAuthenticationSessionId() {
        return authenticationSessionId;
    }

    public void setAuthenticationSessionId(String authenticationSessionId) {
        this.authenticationSessionId = authenticationSessionId;
    }

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
