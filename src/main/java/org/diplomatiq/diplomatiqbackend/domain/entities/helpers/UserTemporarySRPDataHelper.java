package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserTemporarySRPData;
import org.diplomatiq.diplomatiqbackend.domain.entities.utils.ExpirationUtils;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class UserTemporarySRPDataHelper {
    private static final Duration USER_TEMPORARY_SRP_DATA_VALIDITY = Duration.ofMinutes(2);

    public static UserTemporarySRPData create(byte[] serverEphemeral) {
        UserTemporarySRPData userTemporarySRPData = new UserTemporarySRPData();
        ExpirationUtils.setExpirationLifeSpan(userTemporarySRPData, USER_TEMPORARY_SRP_DATA_VALIDITY);
        userTemporarySRPData.setServerEphemeral(serverEphemeral);
        return userTemporarySRPData;
    }
}
