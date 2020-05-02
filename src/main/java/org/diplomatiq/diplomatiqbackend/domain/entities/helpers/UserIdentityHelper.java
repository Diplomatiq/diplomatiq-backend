package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;

import java.util.Collections;
import java.util.Comparator;
import java.util.NoSuchElementException;

public class UserIdentityHelper {
    private static final int EMAIL_VALIDATION_KEY_LENGTH = 150;

    public static UserIdentity create(String emailAddress, String firstName, String lastName) {
        UserIdentity userIdentity = new UserIdentity();

        userIdentity.setEmailAddress(emailAddress);
        userIdentity.setFirstName(firstName);
        userIdentity.setLastName(lastName);
        userIdentity.setEmailValidated(false);
        userIdentity.setEmailValidationKey(RandomUtils.alphanumericString(EMAIL_VALIDATION_KEY_LENGTH));

        return userIdentity;
    }

    public static UserAuthentication getCurrentAuthentication(UserIdentity userIdentity) {
        return Collections.max(userIdentity.getAuthentications(),
            Comparator.comparingLong(UserAuthentication::getVersion));
    }

    public static long getNextAuthenticationVersion(UserIdentity userIdentity) {
        try {
            UserAuthentication userAuthentication = getCurrentAuthentication(userIdentity);
            return userAuthentication.getVersion() + 1;
        } catch (NoSuchElementException ex) {
            return 1;
        }
    }
}
