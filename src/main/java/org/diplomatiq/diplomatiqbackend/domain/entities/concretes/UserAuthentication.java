package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractCreationRecordedNodeEntity;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

import java.util.HashSet;
import java.util.Set;

@NodeEntity
public class UserAuthentication extends AbstractCreationRecordedNodeEntity {
    private long version;

//    @Convert(EncryptedStringConverter.class)
    private String srpSaltHex;

//    @Convert(EncryptedStringConverter.class)
    private String srpVerifierHex;

    private PasswordStretchingAlgorithm passwordStretchingAlgorithm;

    @Relationship(type = "IS_CURRENTLY_AUTHENTICATING_WITH_SRP_DATA")
    private Set<UserTemporarySRPData> userTemporarySrpDatas = new HashSet<>();

    @Relationship(type = "HAS_AUTHENTICATION_SESSION")
    private Set<AuthenticationSession> authenticationSessions = new HashSet<>();

    @Relationship(type = "HAS_RESET_REQUESTED")
    private Set<UserAuthenticationResetRequest> userAuthenticationResetRequests = new HashSet<>();

    @Relationship(type = "AUTHENTICATES_WITH", direction = Relationship.INCOMING)
    private UserIdentity userIdentity;

    public long getVersion() {
        return version;
    }

    public void setVersion(long version) {
        this.version = version;
    }

    public String getSrpSaltHex() {
        return srpSaltHex;
    }

    public void setSrpSaltHex(String srpSaltHex) {
        this.srpSaltHex = srpSaltHex;
    }

    public String getSrpVerifierHex() {
        return srpVerifierHex;
    }

    public void setSrpVerifierHex(String srpVerifierHex) {
        this.srpVerifierHex = srpVerifierHex;
    }

    public PasswordStretchingAlgorithm getPasswordStretchingAlgorithm() {
        return passwordStretchingAlgorithm;
    }

    public void setPasswordStretchingAlgorithm(PasswordStretchingAlgorithm passwordStretchingAlgorithm) {
        this.passwordStretchingAlgorithm = passwordStretchingAlgorithm;
    }

    public Set<UserTemporarySRPData> getUserTemporarySrpDatas() {
        return userTemporarySrpDatas;
    }

    public void setUserTemporarySrpDatas(Set<UserTemporarySRPData> userTemporarySrpDatas) {
        this.userTemporarySrpDatas = userTemporarySrpDatas;
    }

    public Set<AuthenticationSession> getAuthenticationSessions() {
        return authenticationSessions;
    }

    public void setAuthenticationSessions(Set<AuthenticationSession> authenticationSessions) {
        this.authenticationSessions = authenticationSessions;
    }

    public Set<UserAuthenticationResetRequest> getUserAuthenticationResetRequests() {
        return userAuthenticationResetRequests;
    }

    public void setUserAuthenticationResetRequests(Set<UserAuthenticationResetRequest> userAuthenticationResetRequests) {
        this.userAuthenticationResetRequests = userAuthenticationResetRequests;
    }

    public UserIdentity getUserIdentity() {
        return userIdentity;
    }

    public void setUserIdentity(UserIdentity userIdentity) {
        this.userIdentity = userIdentity;
    }
}
