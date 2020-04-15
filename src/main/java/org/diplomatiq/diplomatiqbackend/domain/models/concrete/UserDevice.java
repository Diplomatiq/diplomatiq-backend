package org.diplomatiq.diplomatiqbackend.domain.models.concrete;

import org.diplomatiq.diplomatiqbackend.domain.models.base.AbstractCreationRecordedNodeEntity;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

import java.util.Set;

@NodeEntity
public class UserDevice extends AbstractCreationRecordedNodeEntity {
    private byte[] deviceKey;
    private byte[] sessionToken;

    @Relationship(type = "STORES_DATA_IN")
    private Set<UserDeviceContainer> userDeviceContainers;

    @Relationship(type = "HAS_SESSION")
    private Session session;

    @Relationship(type = "USES_DIPLOMATIQ_ON", direction = Relationship.INCOMING)
    private UserIdentity userIdentity;

    public byte[] getDeviceKey() {
        return deviceKey;
    }

    public void setDeviceKey(byte[] deviceKey) {
        this.deviceKey = deviceKey;
    }

    public byte[] getSessionToken() {
        return sessionToken;
    }

    public void setSessionToken(byte[] sessionToken) {
        this.sessionToken = sessionToken;
    }

    public Set<UserDeviceContainer> getUserDeviceContainers() {
        return userDeviceContainers;
    }

    public void setUserDeviceContainers(Set<UserDeviceContainer> userDeviceContainers) {
        this.userDeviceContainers = userDeviceContainers;
    }

    public Session getSession() {
        return session;
    }

    public void setSession(Session session) {
        this.session = session;
    }

    public UserIdentity getUserIdentity() {
        return userIdentity;
    }

    public void setUserIdentity(UserIdentity userIdentity) {
        this.userIdentity = userIdentity;
    }
}
