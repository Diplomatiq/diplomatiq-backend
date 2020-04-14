package org.diplomatiq.diplomatiqbackend.domain.models;

import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.Index;
import org.neo4j.ogm.annotation.Relationship;

public class UserDeviceContainer {
    @Id
    @GeneratedValue
    private Long id;

    @Index(unique = true)
    private String deviceContainerId;

    private byte[] deviceContainerKey;

    @Relationship(type = "STORES_DATA_IN", direction = Relationship.INCOMING)
    private UserDevice userDevice;

    public String getDeviceContainerId() {
        return deviceContainerId;
    }

    public void setDeviceContainerId(String deviceContainerId) {
        this.deviceContainerId = deviceContainerId;
    }

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
