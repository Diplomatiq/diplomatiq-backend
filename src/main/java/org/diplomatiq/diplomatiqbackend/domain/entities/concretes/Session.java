package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;
import org.diplomatiq.diplomatiqbackend.methods.descriptors.SessionLevelOfAssurance;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

import java.time.Instant;

@NodeEntity
public class Session extends AbstractExpiringNodeEntity {
    SessionLevelOfAssurance levelOfAssurance;
    Instant levelOfAssuranceExpirationTime;

    @Relationship(type = "HAS_SESSION", direction = Relationship.INCOMING)
    private UserDevice userDevice;

    public SessionLevelOfAssurance getLevelOfAssurance() {
        return levelOfAssurance;
    }

    public void setLevelOfAssurance(SessionLevelOfAssurance levelOfAssurance) {
        this.levelOfAssurance = levelOfAssurance;
    }

    public Instant getLevelOfAssuranceExpirationTime() {
        return levelOfAssuranceExpirationTime;
    }

    public void setLevelOfAssuranceExpirationTime(Instant levelOfAssuranceExpirationTime) {
        this.levelOfAssuranceExpirationTime = levelOfAssuranceExpirationTime;
    }

    public UserDevice getUserDevice() {
        return userDevice;
    }

    public void setUserDevice(UserDevice userDevice) {
        this.userDevice = userDevice;
    }
}
