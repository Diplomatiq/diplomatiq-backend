package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingEngine;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UserIdentityHelper {
    private static final int EMAIL_VALIDATION_KEY_LENGTH = 150;

    @Autowired
    PasswordStretchingEngine passwordStretchingEngine;

    @Autowired
    UserAuthenticationHelper userAuthenticationHelper;

    @Autowired
    UserDeviceHelper userDeviceHelper;

    public UserIdentity createUserIdentity(String emailAddress, String firstName, String lastName) {
        UserIdentity userIdentity = new UserIdentity();

        userIdentity.setEmailAddress(emailAddress.toLowerCase());
        userIdentity.setFirstName(firstName);
        userIdentity.setLastName(lastName);
        userIdentity.setEmailValidated(false);
        userIdentity.setEmailValidationKey(RandomUtils.alphanumericString(EMAIL_VALIDATION_KEY_LENGTH));

        return userIdentity;
    }
}
