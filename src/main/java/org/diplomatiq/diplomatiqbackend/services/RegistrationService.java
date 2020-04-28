package org.diplomatiq.diplomatiqbackend.services;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserAuthenticationHelper;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
import org.diplomatiq.diplomatiqbackend.engines.mail.EmailSendingEngine;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.RegisterUserV1Request;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
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
        String emailAddress = request.getEmailAddress().toLowerCase();

        if (userIdentityRepository.existsByEmailAddress(emailAddress)) {
            return;
        }

        UserIdentity userIdentity = userIdentityHelper.create(emailAddress,
            request.getFirstName(), request.getLastName());

        String srpSaltHex = request.getSrpSaltHex();
        String srpVerifierHex = request.getSrpVerifierHex();

        UserAuthentication userAuthentication =
            userAuthenticationHelper.create(userIdentity, srpSaltHex, srpVerifierHex,
                request.getPasswordStretchingAlgorithm());

        userIdentity.setAuthentications(Set.of(userAuthentication));
        userIdentityRepository.save(userIdentity);

        emailSendingEngine.sendEmailAddressValidationEmail(userIdentity);
    }
}
