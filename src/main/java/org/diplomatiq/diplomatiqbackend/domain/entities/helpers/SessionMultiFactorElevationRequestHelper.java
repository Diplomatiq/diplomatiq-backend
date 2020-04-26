package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.SessionMultiFactorElevationRequest;
import org.diplomatiq.diplomatiqbackend.domain.entities.utils.ExpirationUtils;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class SessionMultiFactorElevationRequestHelper {
    private static final Duration SESSION_MULTI_FACTOR_ELEVATION_REQUEST_VALIDITY = Duration.ofMinutes(5);
    private static final int SESSION_MULTI_FACTOR_ELEVATION_REQUEST_CODE_LENGTH = 8;

    public SessionMultiFactorElevationRequest create() {
        SessionMultiFactorElevationRequest sessionMultiFactorElevationRequest =
            new SessionMultiFactorElevationRequest();
        ExpirationUtils.setExpirationLifeSpan(sessionMultiFactorElevationRequest,
            SESSION_MULTI_FACTOR_ELEVATION_REQUEST_VALIDITY);
        sessionMultiFactorElevationRequest.setRequestCode(
            RandomUtils.numericString(SESSION_MULTI_FACTOR_ELEVATION_REQUEST_CODE_LENGTH));
        return sessionMultiFactorElevationRequest;
    }
}
