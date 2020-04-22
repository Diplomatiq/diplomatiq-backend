package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractCreationRecordedNodeEntity;
import org.neo4j.ogm.annotation.*;

import java.util.Collections;
import java.util.Comparator;
import java.util.Set;

@NodeEntity
public class UserIdentity extends AbstractCreationRecordedNodeEntity {
    @Index(unique = true)
    private String emailAddress;

    private String firstName;

    private String lastName;

    private boolean validated;

    @Relationship(type = "AUTHENTICATES_WITH")
    private Set<UserAuthentication> authentications;

    @Relationship(type = "USES_DIPLOMATIQ_ON")
    private Set<UserDevice> devices;

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public boolean isValidated() {
        return validated;
    }

    public void setValidated(boolean validated) {
        this.validated = validated;
    }

    public Set<UserAuthentication> getAuthentications() {
        return authentications;
    }

    public void setAuthentications(Set<UserAuthentication> authentications) {
        this.authentications = authentications;
    }

    public Set<UserDevice> getDevices() {
        return devices;
    }

    public void setDevices(Set<UserDevice> devices) {
        this.devices = devices;
    }

    public UserAuthentication getCurrentAuthentication() {
        return Collections.max(authentications, Comparator.comparingLong(UserAuthentication::getVersion));
    }
}
