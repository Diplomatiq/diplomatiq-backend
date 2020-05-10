package org.diplomatiq.diplomatiqbackend.services;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserDevice;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.engines.mail.EmailSendingEngine;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.BadRequestException;
import org.diplomatiq.diplomatiqbackend.repositories.UserAuthenticationRepository;
import org.diplomatiq.diplomatiqbackend.repositories.UserDeviceRepository;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.LocalDate;

@Service
@Transactional
public class AccountDeletionService {
    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private EmailSendingEngine emailSendingEngine;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private UserDeviceRepository userDeviceRepository;

    @Autowired
    private UserAuthenticationRepository userAuthenticationRepository;

    public void deleteUserAccountV1() throws IOException {
        UserIdentity userIdentity =
            userIdentityRepository.findById(authenticationService.getCurrentUserIdentity().getId()).orElseThrow();

        if (userIdentity.getConferences().removeIf(c -> LocalDate.now().isBefore(c.getTo()))) {
            throw new BadRequestException("Cannot delete account with active applications.");
        }

        if (userIdentity.getOrganizedConferences().removeIf(c -> LocalDate.now().isBefore(c.getTo()))) {
            throw new BadRequestException("Cannot delete account with active organized conferences.");
        }

        String emailAddress = userIdentity.getEmailAddress();
        String firstName = userIdentity.getFirstName();
        String lastName = userIdentity.getLastName();

        for (UserDevice userDevice : userIdentity.getDevices()) {
            userDeviceRepository.delete(userDevice);
        }

        for (UserAuthentication userAuthentication : userIdentity.getAuthentications()) {
            userAuthenticationRepository.delete(userAuthentication);
        }

        userIdentity.setEmailAddress("deleted@deleted.deleted");
        userIdentity.setFirstName("Deleted");
        userIdentity.setLastName("Deleted");

        emailSendingEngine.sendAccountDeletionEmail(emailAddress, firstName, lastName);
    }
}
