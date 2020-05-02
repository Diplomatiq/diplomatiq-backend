package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.AuthenticationSessionMultiFactorElevationRequest;
import org.diplomatiq.diplomatiqbackend.domain.entities.utils.ExpirationUtils;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;

import java.time.Duration;

public class AuthenticationSessionMultiFactorElevationRequestHelper {
    private static final Duration AUTHENTICATION_SESSION_MULTI_FACTOR_ELEVATION_REQUEST_VALIDITY =
        Duration.ofMinutes(5);
    private static final int AUTHENTICATION_SESSION_MULTI_FACTOR_ELEVATION_REQUEST_CODE_LENGTH = 8;

    public static AuthenticationSessionMultiFactorElevationRequest create() {
        AuthenticationSessionMultiFactorElevationRequest authenticationSessionMultiFactorElevationRequest =
            new AuthenticationSessionMultiFactorElevationRequest();
        ExpirationUtils.setExpirationLifeSpan(authenticationSessionMultiFactorElevationRequest,
            AUTHENTICATION_SESSION_MULTI_FACTOR_ELEVATION_REQUEST_VALIDITY);
        authenticationSessionMultiFactorElevationRequest.setRequestCode(
            RandomUtils.numericString(AUTHENTICATION_SESSION_MULTI_FACTOR_ELEVATION_REQUEST_CODE_LENGTH));
        return authenticationSessionMultiFactorElevationRequest;
    }
}
