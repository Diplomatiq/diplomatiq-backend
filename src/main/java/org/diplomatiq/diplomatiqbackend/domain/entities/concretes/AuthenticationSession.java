package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.converters.EncryptedBytesConverter;
import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;
import org.diplomatiq.diplomatiqbackend.methods.attributes.SessionAssuranceLevel;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;
import org.neo4j.ogm.annotation.typeconversion.Convert;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@NodeEntity
public class AuthenticationSession extends AbstractExpiringNodeEntity {
    @Convert(EncryptedBytesConverter.class)
    private byte[] authenticationSessionKey;

    SessionAssuranceLevel assuranceLevel;
    Instant assuranceLevelExpirationTime;

    @Relationship(type = "HAS_ELEVATION_REQUEST")
    private Set<AuthenticationSessionMultiFactorElevationRequest> authenticationSessionMultiFactorElevationRequests =
        new HashSet<>();

    @Relationship(type = "HAS_AUTHENTICATION_SESSION", direction = Relationship.INCOMING)
    private UserAuthentication userAuthentication;

    public byte[] getAuthenticationSessionKey() {
        return authenticationSessionKey;
    }

    public void setAuthenticationSessionKey(byte[] authenticationSessionKey) {
        this.authenticationSessionKey = authenticationSessionKey;
    }

    public SessionAssuranceLevel getAssuranceLevel() {
        return assuranceLevel;
    }

    public void setAssuranceLevel(SessionAssuranceLevel assuranceLevel) {
        this.assuranceLevel = assuranceLevel;
    }

    public Instant getAssuranceLevelExpirationTime() {
        return assuranceLevelExpirationTime;
    }

    public void setAssuranceLevelExpirationTime(Instant assuranceLevelExpirationTime) {
        this.assuranceLevelExpirationTime = assuranceLevelExpirationTime;
    }

    public Set<AuthenticationSessionMultiFactorElevationRequest> getAuthenticationSessionMultiFactorElevationRequests() {
        return authenticationSessionMultiFactorElevationRequests;
    }

    public void setAuthenticationSessionMultiFactorElevationRequests(Set<AuthenticationSessionMultiFactorElevationRequest> authenticationSessionMultiFactorElevationRequests) {
        this.authenticationSessionMultiFactorElevationRequests = authenticationSessionMultiFactorElevationRequests;
    }

    public UserAuthentication getUserAuthentication() {
        return userAuthentication;
    }

    public void setUserAuthentication(UserAuthentication userAuthentication) {
        this.userAuthentication = userAuthentication;
    }
}
