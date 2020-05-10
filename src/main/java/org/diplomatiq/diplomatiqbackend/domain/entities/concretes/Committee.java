package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractCreationRecordedNodeEntity;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

import java.util.HashSet;
import java.util.Set;

@NodeEntity
public class Committee extends AbstractCreationRecordedNodeEntity {
    private String name;

    private String codeName;

    @Relationship(type = "HAS_PLACE")
    private Set<CommitteeSeat> committeeSeats = new HashSet<>();

    @Relationship(type = "HAS_COMMITTEE", direction = Relationship.INCOMING)
    private Conference conference;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCodeName() {
        return codeName;
    }

    public void setCodeName(String code) {
        this.codeName = code;
    }

    public Set<CommitteeSeat> getCommitteeSeats() {
        return committeeSeats;
    }

    public void setCommitteeSeats(Set<CommitteeSeat> committeeSeats) {
        this.committeeSeats = committeeSeats;
    }

    public Conference getConference() {
        return conference;
    }

    public void setConference(Conference conference) {
        this.conference = conference;
    }
}
