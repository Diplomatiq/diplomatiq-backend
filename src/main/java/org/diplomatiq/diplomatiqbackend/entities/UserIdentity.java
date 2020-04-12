package org.diplomatiq.diplomatiqbackend.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.NodeEntity;

@NodeEntity
public class UserIdentity {

    @Id
    @GeneratedValue
    @JsonIgnore
    private Long id;

    private String emailAddress;

    public UserIdentity(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public Long getId() {
        return id;
    }

    public String getEmailAddress() {
        return emailAddress;
    }
}
