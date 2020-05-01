package org.diplomatiq.diplomatiqbackend.methods.controllers;

import com.sendgrid.Request;
import com.sendgrid.SendGrid;
import org.bouncycastle.crypto.CryptoException;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.AuthenticationSession;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserDeviceHelper;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
import org.diplomatiq.diplomatiqbackend.methods.utils.HeadersProvider;
import org.diplomatiq.diplomatiqbackend.methods.utils.TestUtils;
import org.diplomatiq.diplomatiqbackend.repositories.*;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class PasswordElevatedAuthenticationSessionMethodsTests {
    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private UserAuthenticationRepository userAuthenticationRepository;

    @Autowired
    private UserTemporarySRPDataRepository userTemporarySRPDataRepository;

    @Autowired
    private UserDeviceRepository userDeviceRepository;

    @Autowired
    private AuthenticationSessionRepository authenticationSessionRepository;

    @Autowired
    private UserIdentityHelper userIdentityHelper;

    @Autowired
    private UserDeviceHelper userDeviceHelper;

    @Autowired
    private TestUtils testUtils;

    @MockBean
    SendGrid sendGridApiClient;

    @Test
    public void elevateAuthenticationSessionInitV1_shouldSendEmailToUser() throws IOException, BadPaddingException,
        InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException,
        NoSuchPaddingException, CryptoException {
        String password = "secret";
        String emailAddress = testUtils.registerUser(password);
        String authenticationSessionId = testUtils.getAuthenticationSession(emailAddress, password);
        AuthenticationSession authenticationSession =
            authenticationSessionRepository.findById(authenticationSessionId).orElseThrow();

        String uri = "/elevate-authentication-session-init-v1";
        webTestClient.post().uri(uri)
            .headers(httpHeaders -> {
                try {
                    HeadersProvider.authenticationSessionSignatureV1(httpHeaders, "POST", uri, "", "",
                        authenticationSessionId,
                        authenticationSession.getAuthenticationSessionKey());
                } catch (Exception e) {
                    throw new RuntimeException();
                }
            })
            .exchange()
            .expectStatus().isOk()
            .expectBody().isEmpty();

        Mockito.verify(sendGridApiClient, Mockito.times(2)).api(Mockito.any(Request.class));
    }
}
