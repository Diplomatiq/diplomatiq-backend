package org.diplomatiq.diplomatiqbackend.domain.models;

import org.diplomatiq.diplomatiqbackend.utils.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

import java.util.Set;

@NodeEntity
public class UserAuthentication {
    @Id
    @GeneratedValue
    private Long id;

    private Long version;

    private byte[] srpSalt;

    private byte[] srpVerifier;

    private PasswordStretchingAlgorithm passwordStretchingAlgorithm;

    @Relationship(type = "AUTHENTICATES_WITH", direction = Relationship.INCOMING)
    private UserIdentity userIdentity;

    @Relationship(type = "IS_CURRENTLY_LOGGING_IN_WITH_SRP_DATA")
    private Set<UserTemporarySRPLoginData> userTemporarySrpLoginData;

    @Relationship(type = "IS_CURRENTLY_LOGGING_IN_WITH_AUTHENTICATION_SESSION")
    private Set<AuthenticationSession> authenticationSessions;

    public Long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    public byte[] getSrpSalt() {
        return srpSalt;
    }

    public void setSrpSalt(byte[] srpSalt) {
        this.srpSalt = srpSalt;
    }

    public byte[] getSrpVerifier() {
        return srpVerifier;
    }

    public void setSrpVerifier(byte[] srpVerifier) {
        this.srpVerifier = srpVerifier;
    }

    public PasswordStretchingAlgorithm getPasswordStretchingAlgorithm() {
        return passwordStretchingAlgorithm;
    }

    public void setPasswordStretchingAlgorithm(PasswordStretchingAlgorithm passwordStretchingAlgorithm) {
        this.passwordStretchingAlgorithm = passwordStretchingAlgorithm;
    }

    public UserIdentity getUserIdentity() {
        return userIdentity;
    }

    public void setUserIdentity(UserIdentity userIdentity) {
        this.userIdentity = userIdentity;
    }

    public Set<UserTemporarySRPLoginData> getUserTemporarySrpLoginData() {
        return userTemporarySrpLoginData;
    }

    public void setUserTemporarySrpLoginData(Set<UserTemporarySRPLoginData> userTemporarySrpLoginData) {
        this.userTemporarySrpLoginData = userTemporarySrpLoginData;
    }

    public Set<AuthenticationSession> getAuthenticationSessions() {
        return authenticationSessions;
    }

    public void setAuthenticationSessions(Set<AuthenticationSession> authenticationSessions) {
        this.authenticationSessions = authenticationSessions;
    }
}
