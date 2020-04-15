package org.diplomatiq.diplomatiqbackend.domain.models.concrete;

import org.diplomatiq.diplomatiqbackend.domain.models.base.AbstractExpiringNodeEntity;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

@NodeEntity
public class Session extends AbstractExpiringNodeEntity {
    @Relationship(type = "HAS_SESSION", direction = Relationship.INCOMING)
    private UserDevice userDevice;

    public UserDevice getUserDevice() {
        return userDevice;
    }

    public void setUserDevice(UserDevice userDevice) {
        this.userDevice = userDevice;
    }
}
