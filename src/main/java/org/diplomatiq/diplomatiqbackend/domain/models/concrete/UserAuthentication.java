package org.diplomatiq.diplomatiqbackend.domain.models.concrete;

import org.diplomatiq.diplomatiqbackend.domain.models.base.AbstractCreationRecordedNodeEntity;
import org.diplomatiq.diplomatiqbackend.utils.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

import java.util.Set;

@NodeEntity
public class UserAuthentication extends AbstractCreationRecordedNodeEntity {
    private Long version;
    private byte[] srpSalt;
    private byte[] srpVerifier;
    private PasswordStretchingAlgorithm passwordStretchingAlgorithm;

    @Relationship(type = "IS_CURRENTLY_LOGGING_IN_WITH_SRP_DATA")
    private Set<UserTemporarySRPLoginData> userTemporarySrpLoginDatas;

    @Relationship(type = "HAS_AUTHENTICATION_SESSION")
    private Set<AuthenticationSession> authenticationSessions;

    @Relationship(type = "AUTHENTICATES_WITH", direction = Relationship.INCOMING)
    private UserIdentity userIdentity;

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

    public Set<UserTemporarySRPLoginData> getUserTemporarySrpLoginDatas() {
        return userTemporarySrpLoginDatas;
    }

    public void setUserTemporarySrpLoginDatas(Set<UserTemporarySRPLoginData> userTemporarySrpLoginDatas) {
        this.userTemporarySrpLoginDatas = userTemporarySrpLoginDatas;
    }

    public Set<AuthenticationSession> getAuthenticationSessions() {
        return authenticationSessions;
    }

    public void setAuthenticationSessions(Set<AuthenticationSession> authenticationSessions) {
        this.authenticationSessions = authenticationSessions;
    }

    public UserIdentity getUserIdentity() {
        return userIdentity;
    }

    public void setUserIdentity(UserIdentity userIdentity) {
        this.userIdentity = userIdentity;
    }
}
