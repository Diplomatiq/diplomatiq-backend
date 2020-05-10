package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractCreationRecordedNodeEntity;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;

@NodeEntity
public class Conference extends AbstractCreationRecordedNodeEntity {
    private String name;

    private String codeName;

    private LocalDate from;

    private LocalDate to;

    private String country;

    private String city;

    private String address;

    private String postalCode;

    @Relationship(type = "HAS_COMMITTEE")
    private Set<Committee> committees = new HashSet<>();

    @Relationship(type = "PARTICIPATES", direction = Relationship.INCOMING)
    private Set<UserIdentity> delegates = new HashSet<>();

    @Relationship(type = "ORGANIZES", direction = Relationship.INCOMING)
    private UserIdentity organizer;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCodeName() {
        return codeName;
    }

    public void setCodeName(String codeName) {
        this.codeName = codeName;
    }

    public LocalDate getFrom() {
        return from;
    }

    public void setFrom(LocalDate from) {
        this.from = from;
    }

    public LocalDate getTo() {
        return to;
    }

    public void setTo(LocalDate to) {
        this.to = to;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getPostalCode() {
        return postalCode;
    }

    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    public Set<Committee> getCommittees() {
        return committees;
    }

    public void setCommittees(Set<Committee> committees) {
        this.committees = committees;
    }

    public Set<UserIdentity> getDelegates() {
        return delegates;
    }

    public void setDelegates(Set<UserIdentity> delegates) {
        this.delegates = delegates;
    }

    public UserIdentity getOrganizer() {
        return organizer;
    }

    public void setOrganizer(UserIdentity organizer) {
        this.organizer = organizer;
    }
}
