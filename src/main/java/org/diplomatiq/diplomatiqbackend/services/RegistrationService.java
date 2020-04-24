package org.diplomatiq.diplomatiqbackend.services;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserAuthenticationHelper;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
import org.diplomatiq.diplomatiqbackend.engines.mail.EmailSendingEngine;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.BadRequestException;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.RegisterUserV1Request;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Base64;
import java.util.Set;

@Service
@Transactional
public class RegistrationService {
    @Autowired
    private EmailSendingEngine emailSendingEngine;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private UserIdentityHelper userIdentityHelper;

    @Autowired
    private UserAuthenticationHelper userAuthenticationHelper;

    public void registerUserV1(RegisterUserV1Request request) throws IOException {
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

        UserIdentity userIdentity = userIdentityHelper.createUserIdentity(request.getEmailAddress(),
            request.getFirstName(), request.getLastName());

        UserAuthentication userAuthentication =
            userAuthenticationHelper.createUserAuthentication(userIdentity, srpSalt, srpVerifier,
                request.getPasswordStretchingAlgorithm());

        userIdentity.setAuthentications(Set.of(userAuthentication));
        userIdentityRepository.save(userIdentity);

        emailSendingEngine.sendEmailAddressValidationEmail(userIdentity);
    }
}
