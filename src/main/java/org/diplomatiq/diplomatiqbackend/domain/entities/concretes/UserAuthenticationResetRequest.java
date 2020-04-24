package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;
import org.neo4j.ogm.annotation.Index;
import org.neo4j.ogm.annotation.Relationship;

public class UserAuthenticationResetRequest extends AbstractExpiringNodeEntity {
    @Index(unique = true)
    private String requestKey;

    @Relationship(type = "HAS_RESET_REQUESTED", direction = Relationship.INCOMING)
    private UserAuthentication userAuthentication;

    public String getRequestKey() {
        return requestKey;
    }

    public void setRequestKey(String requestKey) {
        this.requestKey = requestKey;
    }

    public UserAuthentication getUserAuthentication() {
        return userAuthentication;
    }

    public void setUserAuthentication(UserAuthentication userAuthentication) {
        this.userAuthentication = userAuthentication;
    }
}
