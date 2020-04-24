package org.diplomatiq.diplomatiqbackend.domain.entities.concretes;

import org.diplomatiq.diplomatiqbackend.domain.converters.EncryptedBytesConverter;
import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractCreationRecordedNodeEntity;
import org.neo4j.ogm.annotation.Relationship;
import org.neo4j.ogm.annotation.typeconversion.Convert;

public class UserTemporarySRPData extends AbstractCreationRecordedNodeEntity {
    @Convert(EncryptedBytesConverter.class)
    private byte[] serverEphemeral;

    @Relationship(type = "IS_CURRENTLY_AUTHENTICATING_WITH_SRP_DATA", direction = Relationship.INCOMING)
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
