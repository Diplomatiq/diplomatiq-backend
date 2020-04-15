package org.diplomatiq.diplomatiqbackend.domain.models.concrete;

import org.diplomatiq.diplomatiqbackend.domain.models.base.AbstractCreationRecordedNodeEntity;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

@NodeEntity
public class UserDeviceContainer extends AbstractCreationRecordedNodeEntity {
    private byte[] deviceContainerKey;

    @Relationship(type = "STORES_DATA_IN", direction = Relationship.INCOMING)
    private UserDevice userDevice;

    public byte[] getDeviceContainerKey() {
        return deviceContainerKey;
    }

    public void setDeviceContainerKey(byte[] deviceContainerKey) {
        this.deviceContainerKey = deviceContainerKey;
    }

    public UserDevice getUserDevice() {
        return userDevice;
    }

    public void setUserDevice(UserDevice userDevice) {
        this.userDevice = userDevice;
    }
}
