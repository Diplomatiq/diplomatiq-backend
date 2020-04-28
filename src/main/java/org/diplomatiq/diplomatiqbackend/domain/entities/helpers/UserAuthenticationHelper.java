package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingEngine;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UserAuthenticationHelper {
    @Autowired
    private PasswordStretchingEngine passwordStretchingEngine;

    @Autowired
    private UserIdentityHelper userIdentityHelper;

    public UserAuthentication create(UserIdentity userIdentity, String srpSaltHex, String srpVerifierHex,
                                     PasswordStretchingAlgorithm passwordStretchingAlgorithm) {
        UserAuthentication userAuthentication = new UserAuthentication();

        userAuthentication.setVersion(userIdentityHelper.getNextAuthenticationVersion(userIdentity));
        userAuthentication.setSrpSaltHex(srpSaltHex);
        userAuthentication.setSrpVerifierHex(srpVerifierHex);
        userAuthentication.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);

        return userAuthentication;
    }
}
