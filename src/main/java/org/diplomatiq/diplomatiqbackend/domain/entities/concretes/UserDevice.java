package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.converters.EncryptedBytesConverter;
import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractCreationRecordedNodeEntity;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;
import org.neo4j.ogm.annotation.typeconversion.Convert;

@NodeEntity
public class UserDevice extends AbstractCreationRecordedNodeEntity {
    @Convert(EncryptedBytesConverter.class)
    private byte[] deviceKey;

    @Convert(EncryptedBytesConverter.class)
    private byte[] deviceContainerKey;

    @Convert(EncryptedBytesConverter.class)
    private byte[] sessionToken;

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

    public byte[] getDeviceContainerKey() {
        return deviceContainerKey;
    }

    public void setDeviceContainerKey(byte[] deviceContainerKey) {
        this.deviceContainerKey = deviceContainerKey;
    }

    public byte[] getSessionToken() {
        return sessionToken;
    }

    public void setSessionToken(byte[] sessionToken) {
        this.sessionToken = sessionToken;
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
