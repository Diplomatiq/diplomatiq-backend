package org.diplomatiq.diplomatiqbackend.domain.models;

import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.Index;
import org.neo4j.ogm.annotation.Relationship;

public class UserDevice {
    @Id
    @GeneratedValue
    private Long id;

    @Index(unique = true)
    private String deviceId;

    private byte[] deviceKey;

    @Relationship(type = "STORES_DATA_IN")
    private UserDeviceContainer userDeviceContainer;

    @Relationship(type = "USES_DIPLOMATIQ_ON", direction = Relationship.INCOMING)
    private UserIdentity userIdentity;

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public byte[] getDeviceKey() {
        return deviceKey;
    }

    public void setDeviceKey(byte[] deviceKey) {
        this.deviceKey = deviceKey;
    }

    public UserDeviceContainer getUserDeviceContainer() {
        return userDeviceContainer;
    }

    public void setUserDeviceContainer(UserDeviceContainer userDeviceContainer) {
        this.userDeviceContainer = userDeviceContainer;
    }

    public UserIdentity getUserIdentity() {
        return userIdentity;
    }

    public void setUserIdentity(UserIdentity userIdentity) {
        this.userIdentity = userIdentity;
    }
}
