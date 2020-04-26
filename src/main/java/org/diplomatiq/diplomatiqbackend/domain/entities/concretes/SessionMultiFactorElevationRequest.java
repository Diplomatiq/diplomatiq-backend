package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;
import org.neo4j.ogm.annotation.Relationship;

public class SessionMultiFactorElevationRequest extends AbstractExpiringNodeEntity {
    private String requestCode;

    @Relationship(type = "HAS_ELEVATION_REQUEST", direction = Relationship.INCOMING)
    private Session session;

    public String getRequestCode() {
        return requestCode;
    }

    public void setRequestCode(String requestCode) {
        this.requestCode = requestCode;
    }

    public Session getSession() {
        return session;
    }

    public void setSession(Session session) {
        this.session = session;
    }
}
