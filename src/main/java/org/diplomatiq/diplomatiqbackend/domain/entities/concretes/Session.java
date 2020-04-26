package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;
import org.diplomatiq.diplomatiqbackend.methods.attributes.SessionAssuranceLevel;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@NodeEntity
public class Session extends AbstractExpiringNodeEntity {
    SessionAssuranceLevel assuranceLevel;
    Instant assuranceLevelExpirationTime;

    @Relationship(type = "HAS_ELEVATION_REQUEST")
    private Set<SessionMultiFactorElevationRequest> sessionMultiFactorElevationRequests = new HashSet<>();

    @Relationship(type = "HAS_SESSION", direction = Relationship.INCOMING)
    private UserDevice userDevice;

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

    public Set<SessionMultiFactorElevationRequest> getSessionMultiFactorElevationRequests() {
        return sessionMultiFactorElevationRequests;
    }

    public void setSessionMultiFactorElevationRequests(Set<SessionMultiFactorElevationRequest> sessionMultiFactorElevationRequests) {
        this.sessionMultiFactorElevationRequests = sessionMultiFactorElevationRequests;
    }

    public UserDevice getUserDevice() {
        return userDevice;
    }

    public void setUserDevice(UserDevice userDevice) {
        this.userDevice = userDevice;
    }
}
