package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractExpiringNodeEntity;
import org.neo4j.ogm.annotation.NodeEntity;
import org.neo4j.ogm.annotation.Relationship;

@NodeEntity
public class UserTemporarySRPData extends AbstractExpiringNodeEntity {
//    @Convert(EncryptedStringConverter.class)
    private String serverEphemeralHex;

//    @Convert(EncryptedStringConverter.class)
    private String serverSecretHex;

    @Relationship(type = "IS_CURRENTLY_AUTHENTICATING_WITH_SRP_DATA", direction = Relationship.INCOMING)
    private UserAuthentication userAuthentication;

    public String getServerEphemeralHex() {
        return serverEphemeralHex;
    }

    public void setServerEphemeralHex(String serverEphemeralHex) {
        this.serverEphemeralHex = serverEphemeralHex;
    }

    public String getServerSecretHex() {
        return serverSecretHex;
    }

    public void setServerSecretHex(String serverSecretHex) {
        this.serverSecretHex = serverSecretHex;
    }

    public UserAuthentication getUserAuthentication() {
        return userAuthentication;
    }

    public void setUserAuthentication(UserAuthentication userAuthentication) {
        this.userAuthentication = userAuthentication;
    }
}
