package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserTemporarySRPData;
import org.diplomatiq.diplomatiqbackend.domain.entities.utils.ExpirationUtils;

import java.time.Duration;

public class UserTemporarySRPDataHelper {
    private static final Duration USER_TEMPORARY_SRP_DATA_VALIDITY = Duration.ofMinutes(2);

    public static UserTemporarySRPData create(String serverEphemeralHex, String serverSecretHex) {
        UserTemporarySRPData userTemporarySRPData = new UserTemporarySRPData();
        ExpirationUtils.setExpirationLifeSpan(userTemporarySRPData, USER_TEMPORARY_SRP_DATA_VALIDITY);
        userTemporarySRPData.setServerEphemeralHex(serverEphemeralHex);
        userTemporarySRPData.setServerSecretHex(serverSecretHex);
        return userTemporarySRPData;
    }
}
