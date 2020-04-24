package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthenticationResetRequest;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class UserAuthenticationResetRequestHelper {
    private static final Duration USER_AUTHENTICATION_RESET_REQUEST_HELPER = Duration.ofDays(1);
    private static final int REQUEST_KEY_LENGTH = 150;

    public UserAuthenticationResetRequest create() {
        UserAuthenticationResetRequest userAuthenticationResetRequest = new UserAuthenticationResetRequest();
        userAuthenticationResetRequest.setExpirationTimeDelta(USER_AUTHENTICATION_RESET_REQUEST_HELPER);
        userAuthenticationResetRequest.setRequestKey(RandomUtils.alphanumericString(REQUEST_KEY_LENGTH));
        return userAuthenticationResetRequest;
    }
}
