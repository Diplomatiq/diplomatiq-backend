package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.converters.EncryptedBytesConverter;
import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractCreationRecordedNodeEntity;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;
import org.neo4j.ogm.annotation.typeconversion.Convert;

@NodeEntity
public class UserDeviceContainer extends AbstractCreationRecordedNodeEntity {
    @Convert(EncryptedBytesConverter.class)
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
