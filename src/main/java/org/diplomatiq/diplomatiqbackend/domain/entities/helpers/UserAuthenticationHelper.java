package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingEngine;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UserAuthenticationHelper {
    @Autowired
    private PasswordStretchingEngine passwordStretchingEngine;

    public UserAuthentication createUserAuthenticationForRegistration(byte[] srpSalt, byte[] srpVerifier,
                                                                      PasswordStretchingAlgorithm passwordStretchingAlgorithm) {
        UserAuthentication userAuthentication = new UserAuthentication();

        userAuthentication.setVersion(1L);
        userAuthentication.setSrpSalt(srpSalt);
        userAuthentication.setSrpVerifier(srpVerifier);
        userAuthentication.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);

        return userAuthentication;
    }
}
