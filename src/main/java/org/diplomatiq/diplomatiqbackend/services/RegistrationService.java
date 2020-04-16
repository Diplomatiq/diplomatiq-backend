package org.diplomatiq.diplomatiqbackend.services;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserAuthenticationHelper;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.exceptions.api.BadRequestException;
import org.diplomatiq.diplomatiqbackend.exceptions.api.InternalServerErrorException;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.RegisterUserV1Request;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Set;

@Service
@Transactional
public class RegistrationService {
    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private UserIdentityHelper userIdentityHelper;

    @Autowired
    private UserAuthenticationHelper userAuthenticationHelper;

    public void registerUser(RegisterUserV1Request request) {
        byte[] srpSalt;
        try {
            srpSalt = Base64.getDecoder().decode(request.getSrpSaltBase64());
        } catch (Exception ex) {
            throw new BadRequestException("SRP salt could not be decoded.", ex);
        }

        byte[] srpVerifier;
        try {
            srpVerifier = Base64.getDecoder().decode(request.getSrpSaltBase64());
        } catch (Exception ex) {
            throw new BadRequestException("SRP verifier could not be decoded.", ex);
        }

        PasswordStretchingAlgorithm passwordStretchingAlgorithm;
        try {
            passwordStretchingAlgorithm = PasswordStretchingAlgorithm.valueOf(request.getPasswordStretchingAlgorithm());
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Unknown password stretching algorithm.", ex);
        }

        UserIdentity userIdentity = null;
        try {
            userIdentity = userIdentityHelper.createUserIdentity(request.getEmailAddress(),
                request.getFirstName(), request.getLastName());
        } catch (NoSuchAlgorithmException ex) {
            throw new InternalServerErrorException(null, ex);
        }

        UserAuthentication userAuthentication =
            userAuthenticationHelper.createUserAuthenticationForRegistration(srpSalt, srpVerifier,
                passwordStretchingAlgorithm);

        userIdentity.setAuthentications(Set.of(userAuthentication));
        userIdentityRepository.save(userIdentity);
    }
}
