package org.diplomatiq.diplomatiqbackend.domain.models;

import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.Relationship;

public class UserTemporarySRPLoginData {
    @Id
    @GeneratedValue
    private Long id;

    private byte[] serverEphemeral;

    @Relationship(type = "IS_CURRENTLY_LOGGING_IN_WITH_SRP_DATA", direction = Relationship.INCOMING)
    private UserAuthentication userAuthentication;

    public byte[] getServerEphemeral() {
        return serverEphemeral;
    }

    public void setServerEphemeral(byte[] serverEphemeral) {
        this.serverEphemeral = serverEphemeral;
    }

    public UserAuthentication getUserAuthentication() {
        return userAuthentication;
    }

    public void setUserAuthentication(UserAuthentication userAuthentication) {
        this.userAuthentication = userAuthentication;
    }
}
