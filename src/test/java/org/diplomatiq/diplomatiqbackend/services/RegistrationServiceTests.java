package org.diplomatiq.diplomatiqbackend.services;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.engines.mail.EmailSendingEngine;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.RegisterUserV1Request;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.diplomatiq.diplomatiqbackend.testutils.DummyData;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
public class RegistrationServiceTests {
    @Autowired
    private RegistrationService registrationService;

    @MockBean
    private EmailSendingEngine emailSendingEngine;

    @MockBean
    private UserIdentityRepository userIdentityRepository;

    @Test
    public void registerUserV1_shouldRegisterUser() throws IOException {
        String emailAddress = DummyData.USER_EMAIL;
        String firstName = DummyData.USER_FIRST_NAME;
        String lastName = DummyData.USER_LAST_NAME;
        String srpSaltHex = new BigInteger(1, RandomUtils.bytes(32)).toString(16);
        String srpVerifierHex = new BigInteger(1, RandomUtils.bytes(1024)).toString(16);
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;

        RegisterUserV1Request request = new RegisterUserV1Request();
        request.setEmailAddress(emailAddress);
        request.setFirstName(firstName);
        request.setLastName(lastName);
        request.setSrpSaltHex(srpSaltHex);
        request.setSrpVerifierHex(srpVerifierHex);
        request.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);

        registrationService.registerUserV1(request);

        ArgumentCaptor<UserIdentity> acUserIdentity = ArgumentCaptor.forClass(UserIdentity.class);

        verify(userIdentityRepository, times(1)).existsByEmailAddress(emailAddress);
        verify(userIdentityRepository, times(1)).save(acUserIdentity.capture());
        verify(emailSendingEngine, times(1)).sendEmailAddressValidationEmail(acUserIdentity.capture());
        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(emailSendingEngine);

        List<UserIdentity> capturedUserIdentities = acUserIdentity.getAllValues();

        UserIdentity savedUserIdentity = capturedUserIdentities.remove(0);
        assertEquals(emailAddress, savedUserIdentity.getEmailAddress());
        assertEquals(firstName, savedUserIdentity.getFirstName());
        assertEquals(lastName, savedUserIdentity.getLastName());
        assertFalse(savedUserIdentity.isEmailValidated());
        assertEquals(150, savedUserIdentity.getEmailValidationKey().length());
        assertEquals(1, savedUserIdentity.getAuthentications().size());
        assertEquals(0, savedUserIdentity.getDevices().size());

        UserAuthentication userAuthentication = savedUserIdentity.getAuthentications().iterator().next();
        assertEquals(srpSaltHex, userAuthentication.getSrpSaltHex());
        assertEquals(srpVerifierHex, userAuthentication.getSrpVerifierHex());
        assertEquals(PasswordStretchingAlgorithm.Scrypt_v1,
            userAuthentication.getPasswordStretchingAlgorithm());

        UserIdentity emailedUserIdentity = capturedUserIdentities.remove(0);
        assertEquals(emailAddress, emailedUserIdentity.getEmailAddress());
    }

    @Test
    public void registerUserV1_shouldNotThrowIfUserAlreadyExists() throws IOException {
        String emailAddress = "samsepi0l@diplomatiq.org";
        when(userIdentityRepository.existsByEmailAddress(emailAddress)).thenReturn(true);

        String firstName = "Sam";
        String lastName = "Sepiol";
        String srpSaltHex = new BigInteger(1, RandomUtils.bytes(32)).toString(16);
        String srpVerifierHex = new BigInteger(1, RandomUtils.bytes(1024)).toString(16);
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;

        RegisterUserV1Request request = new RegisterUserV1Request();
        request.setEmailAddress(emailAddress);
        request.setFirstName(firstName);
        request.setLastName(lastName);
        request.setSrpSaltHex(srpSaltHex);
        request.setSrpVerifierHex(srpVerifierHex);
        request.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);

        assertDoesNotThrow(() -> registrationService.registerUserV1(request));
        verify(userIdentityRepository).existsByEmailAddress(emailAddress);
        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoInteractions(emailSendingEngine);
    }
}
