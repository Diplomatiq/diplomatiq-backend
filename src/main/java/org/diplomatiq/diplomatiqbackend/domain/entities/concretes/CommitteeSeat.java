package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractCreationRecordedNodeEntity;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

@NodeEntity
public class CommitteeSeat extends AbstractCreationRecordedNodeEntity {
    private String representedCountry;

    @Relationship(type = "HAS_PLACE", direction = Relationship.INCOMING)
    private Committee committee;

    @Relationship(type = "REPRESENTS", direction = Relationship.INCOMING)
    private UserIdentity delegate;

    public String getRepresentedCountry() {
        return representedCountry;
    }

    public void setRepresentedCountry(String representedCountry) {
        this.representedCountry = representedCountry;
    }

    public Committee getCommittee() {
        return committee;
    }

    public void setCommittee(Committee committee) {
        this.committee = committee;
    }

    public UserIdentity getDelegate() {
        return delegate;
    }

    public void setDelegate(UserIdentity delegate) {
        this.delegate = delegate;
    }
}
