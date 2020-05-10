package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractCreationRecordedNodeEntity;
import org.neo4j.ogm.annotation.Index;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

import java.util.HashSet;
import java.util.Set;

@NodeEntity
public class UserIdentity extends AbstractCreationRecordedNodeEntity {
    @Index(unique = true)
    private String emailAddress;

    private String firstName;

    private String lastName;

    private boolean emailValidated;

    @Index(unique = true)
    private String emailValidationKey;

    @Relationship(type = "AUTHENTICATES_WITH")
    private Set<UserAuthentication> authentications = new HashSet<>();

    @Relationship(type = "USES_DIPLOMATIQ_ON")
    private Set<UserDevice> devices = new HashSet<>();

    @Relationship(type = "ORGANIZES")
    private Set<Conference> organizedConferences = new HashSet<>();

    @Relationship(type = "PARTICIPATES")
    private Set<Conference> conferences = new HashSet<>();

    @Relationship(type = "REPRESENTS")
    private Set<CommitteeSeat> committeeSeats = new HashSet<>();

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

    public boolean isEmailValidated() {
        return emailValidated;
    }

    public void setEmailValidated(boolean emailValidated) {
        this.emailValidated = emailValidated;
    }

    public String getEmailValidationKey() {
        return emailValidationKey;
    }

    public void setEmailValidationKey(String emailValidationKey) {
        this.emailValidationKey = emailValidationKey;
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

    public Set<Conference> getOrganizedConferences() {
        return organizedConferences;
    }

    public void setOrganizedConferences(Set<Conference> organizedConferences) {
        this.organizedConferences = organizedConferences;
    }

    public Set<Conference> getConferences() {
        return conferences;
    }

    public void setConferences(Set<Conference> conferences) {
        this.conferences = conferences;
    }

    public Set<CommitteeSeat> getCommitteeSeats() {
        return committeeSeats;
    }

    public void setCommitteeSeats(Set<CommitteeSeat> committeeSeats) {
        this.committeeSeats = committeeSeats;
    }
}
