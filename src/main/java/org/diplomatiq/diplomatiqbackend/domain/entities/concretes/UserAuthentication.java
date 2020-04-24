package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.converters.EncryptedBytesConverter;
import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractCreationRecordedNodeEntity;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;
import org.neo4j.ogm.annotation.typeconversion.Convert;

import java.util.Set;

@NodeEntity
public class UserAuthentication extends AbstractCreationRecordedNodeEntity {
    private Long version;

    @Convert(EncryptedBytesConverter.class)
    private byte[] srpSalt;

    @Convert(EncryptedBytesConverter.class)
    private byte[] srpVerifier;

    private PasswordStretchingAlgorithm passwordStretchingAlgorithm;

    @Relationship(type = "IS_CURRENTLY_AUTHENTICATING_WITH_SRP_DATA")
    private Set<UserTemporarySRPData> userTemporarySrpDatas;

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

    public UserIdentity getUserIdentity() {
        return userIdentity;
    }

    public void setUserIdentity(UserIdentity userIdentity) {
        this.userIdentity = userIdentity;
    }
}
