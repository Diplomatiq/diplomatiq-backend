package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthenticationResetRequest;
import org.diplomatiq.diplomatiqbackend.domain.entities.utils.ExpirationUtils;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class UserAuthenticationResetRequestHelper {
    private static final Duration USER_AUTHENTICATION_RESET_REQUEST_VALIDITY = Duration.ofDays(1);
    private static final int REQUEST_KEY_LENGTH = 150;

    public UserAuthenticationResetRequest create() {
        UserAuthenticationResetRequest userAuthenticationResetRequest = new UserAuthenticationResetRequest();
        ExpirationUtils.setExpirationLifeSpan(userAuthenticationResetRequest,
            USER_AUTHENTICATION_RESET_REQUEST_VALIDITY);
        userAuthenticationResetRequest.setRequestKey(RandomUtils.alphanumericString(REQUEST_KEY_LENGTH));
        return userAuthenticationResetRequest;
    }
}
