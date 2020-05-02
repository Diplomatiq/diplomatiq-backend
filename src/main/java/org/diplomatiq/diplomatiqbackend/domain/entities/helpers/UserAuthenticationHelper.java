package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;

public class UserAuthenticationHelper {
    public static UserAuthentication create(UserIdentity userIdentity, String srpSaltHex, String srpVerifierHex,
                                     PasswordStretchingAlgorithm passwordStretchingAlgorithm) {
        UserAuthentication userAuthentication = new UserAuthentication();

        userAuthentication.setVersion(UserIdentityHelper.getNextAuthenticationVersion(userIdentity));
        userAuthentication.setSrpSaltHex(srpSaltHex);
        userAuthentication.setSrpVerifierHex(srpVerifierHex);
        userAuthentication.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);

        return userAuthentication;
    }
}
