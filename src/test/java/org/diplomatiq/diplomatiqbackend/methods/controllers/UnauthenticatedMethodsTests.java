package org.diplomatiq.diplomatiqbackend.methods.controllers;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.AuthenticationSession;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserTemporarySRPData;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.methods.attributes.SessionAssuranceLevel;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.PasswordAuthenticationCompleteV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.PasswordAuthenticationInitV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.RegisterUserV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationCompleteV1Response;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationInitV1Response;
import org.diplomatiq.diplomatiqbackend.methods.utils.HeadersProvider;
import org.diplomatiq.diplomatiqbackend.methods.utils.TestUtils;
import org.diplomatiq.diplomatiqbackend.repositories.UserAuthenticationRepository;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.diplomatiq.diplomatiqbackend.repositories.UserTemporarySRPDataRepository;
import org.diplomatiq.diplomatiqbackend.utils.crypto.aead.DiplomatiqAEAD;
import org.diplomatiq.diplomatiqbackend.utils.crypto.convert.BigIntegerToByteArray;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("testing")
public class UnauthenticatedMethodsTests {
    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private UserAuthenticationRepository userAuthenticationRepository;

    @Autowired
    private UserTemporarySRPDataRepository userTemporarySRPDataRepository;

    @Autowired
    private UserIdentityHelper userIdentityHelper;

    @Autowired
    private TestUtils testUtils;

    @Test
    public void registerUserV1_shouldRegisterUser() {
        String emailAddress = "samspi0l@diplomatiq.org";
        String firstName = "Sam";
        String lastName = "Sepiol";
        String srpSaltHex = new BigInteger(1, RandomUtils.bytes(32)).toString(16);
        String srpVerifierHex = new BigInteger(1, RandomUtils.bytes(1024)).toString(16);
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Argon2_v1;

        RegisterUserV1Request request = new RegisterUserV1Request();
        request.setEmailAddress(emailAddress);
        request.setFirstName(firstName);
        request.setLastName(lastName);
        request.setSrpSaltHex(srpSaltHex);
        request.setSrpVerifierHex(srpVerifierHex);
        request.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);

        webTestClient.post().uri("/register-user-v1")
            .headers(HeadersProvider::unauthenticated)
            .body(Mono.just(request), RegisterUserV1Request.class)
            .exchange()
            .expectStatus().isOk()
            .expectBody().isEmpty();

        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();
        Assertions.assertEquals(emailAddress, userIdentity.getEmailAddress());
        Assertions.assertEquals(firstName, userIdentity.getFirstName());
        Assertions.assertEquals(lastName, userIdentity.getLastName());
        Assertions.assertFalse(userIdentity.isEmailValidated());
        Assertions.assertEquals(150, userIdentity.getEmailValidationKey().length());

        Set<UserAuthentication> userAuthentications = userIdentity.getAuthentications();
        Assertions.assertEquals(1, userAuthentications.size());

        UserAuthentication userAuthentication = userIdentityHelper.getCurrentAuthentication(userIdentity);
        Assertions.assertEquals(srpSaltHex, userAuthentication.getSrpSaltHex());
        Assertions.assertEquals(srpVerifierHex, userAuthentication.getSrpVerifierHex());
        Assertions.assertEquals(PasswordStretchingAlgorithm.Argon2_v1,
            userAuthentication.getPasswordStretchingAlgorithm());

        Assertions.assertEquals(0, userIdentity.getDevices().size());
    }

    @Test
    public void registerUserV1_shouldNotThrowIfUserAlreadyExists() throws IOException {
        UserIdentity registeredUser = testUtils.registerUser();

        boolean registeredUserExists = userIdentityRepository.existsByEmailAddress(registeredUser.getEmailAddress());
        Assertions.assertTrue(registeredUserExists);

        String emailAddress = registeredUser.getEmailAddress();
        String firstName = "Sam";
        String lastName = "Sepiol";
        String srpSaltHex = new BigInteger(1, RandomUtils.bytes(32)).toString(16);
        String srpVerifierHex = new BigInteger(1, RandomUtils.bytes(1024)).toString(16);
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Argon2_v1;

        RegisterUserV1Request request = new RegisterUserV1Request();
        request.setEmailAddress(emailAddress);
        request.setFirstName(firstName);
        request.setLastName(lastName);
        request.setSrpSaltHex(srpSaltHex);
        request.setSrpVerifierHex(srpVerifierHex);
        request.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);

        webTestClient.post().uri("/register-user-v1")
            .headers(HeadersProvider::unauthenticated)
            .body(Mono.just(request), RegisterUserV1Request.class)
            .exchange()
            .expectStatus().isOk()
            .expectBody().isEmpty();
    }

    @Test
    public void passwordAuthenticationInitV1_shouldInitPasswordAuthentication() throws IOException {
        String password = "secret";
        UserIdentity userIdentity = testUtils.registerUser(password);
        UserAuthentication userAuthentication =
            userAuthenticationRepository.findById(userIdentityHelper.getCurrentAuthentication(userIdentity).getId())
                .orElseThrow();

        Assertions.assertEquals(0, userAuthentication.getUserTemporarySrpDatas().size());

        PasswordAuthenticationInitV1Request request = new PasswordAuthenticationInitV1Request();
        request.setEmailAddress(userIdentity.getEmailAddress());

        EntityExchangeResult<PasswordAuthenticationInitV1Response> apiResponse =
            webTestClient.post().uri("/password-authentication-init-v1")
                .headers(HeadersProvider::unauthenticated)
                .body(Mono.just(request), PasswordAuthenticationInitV1Request.class)
                .exchange()
                .expectStatus().isOk()
                .expectBody(PasswordAuthenticationInitV1Response.class)
                .returnResult();

        PasswordAuthenticationInitV1Response response = apiResponse.getResponseBody();
        Assertions.assertNotNull(response);

        Assertions.assertEquals(userAuthentication.getSrpSaltHex(), response.getSrpSaltHex());
        Assertions.assertEquals(userAuthentication.getPasswordStretchingAlgorithm(),
            response.getPasswordStretchingAlgorithm());

        Assertions.assertEquals(1, userTemporarySRPDataRepository.count());
        UserTemporarySRPData userTemporarySRPData = userTemporarySRPDataRepository.findAll().iterator().next();
        Assertions.assertEquals(response.getServerEphemeralHex(), userTemporarySRPData.getServerEphemeralHex());
    }

    @Test
    public void passwordAuthenticationInitV1_shouldNotThrowIfUserNotExists() {
        PasswordAuthenticationInitV1Request request = new PasswordAuthenticationInitV1Request();
        request.setEmailAddress("doesnotexist@diplomatiq.org");

        EntityExchangeResult<PasswordAuthenticationInitV1Response> apiResponse =
            webTestClient.post().uri("/password-authentication-init-v1")
                .headers(HeadersProvider::unauthenticated)
                .body(Mono.just(request), PasswordAuthenticationInitV1Request.class)
                .exchange()
                .expectStatus().isOk()
                .expectBody(PasswordAuthenticationInitV1Response.class)
                .returnResult();

        PasswordAuthenticationInitV1Response response = apiResponse.getResponseBody();
        Assertions.assertNotNull(response);
    }

    @Test
    public void passwordAuthenticationCompleteV1_shouldCreateAuthenticationSession() throws IOException,
        CryptoException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String password = "secret";
        UserIdentity userIdentity = testUtils.registerUser(password);

        PasswordAuthenticationInitV1Request initRequest = new PasswordAuthenticationInitV1Request();
        initRequest.setEmailAddress(userIdentity.getEmailAddress());

        EntityExchangeResult<PasswordAuthenticationInitV1Response> initApiResponse =
            webTestClient.post().uri("/password-authentication-init-v1")
                .headers(HeadersProvider::unauthenticated)
                .body(Mono.just(initRequest), PasswordAuthenticationInitV1Request.class)
                .exchange()
                .expectStatus().isOk()
                .expectBody(PasswordAuthenticationInitV1Response.class)
                .consumeWith(r -> {})
                .returnResult();

        PasswordAuthenticationInitV1Response initResponse = initApiResponse.getResponseBody();
        Assertions.assertNotNull(initResponse);

        String srpSaltHex = initResponse.getSrpSaltHex();
        BigInteger srpSaltBigInteger = new BigInteger(srpSaltHex, 16);
        byte[] srpSaltBytes = BigIntegerToByteArray.convert(srpSaltBigInteger);

        byte[] identityBytes = userIdentity.getEmailAddress().getBytes(StandardCharsets.UTF_8);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

        SRP6Client srp6Client = new SRP6Client();
        srp6Client.init(SRP6StandardGroups.rfc5054_8192, new SHA256Digest(), new SecureRandom());
        String clientEphemeralHex = srp6Client.generateClientCredentials(srpSaltBytes, identityBytes,
            passwordBytes).toString(16);

        String serverEphemeralHex = initResponse.getServerEphemeralHex();
        BigInteger serverEphemeralBigInteger = new BigInteger(serverEphemeralHex, 16);
        srp6Client.calculateSecret(serverEphemeralBigInteger);

        BigInteger clientProofBigInteger = srp6Client.calculateClientEvidenceMessage();
        String clientProofHex = clientProofBigInteger.toString(16);

        PasswordAuthenticationCompleteV1Request completeRequest = new PasswordAuthenticationCompleteV1Request();
        completeRequest.setEmailAddress(userIdentity.getEmailAddress());
        completeRequest.setClientEphemeralHex(clientEphemeralHex);
        completeRequest.setClientProofHex(clientProofHex);
        completeRequest.setServerEphemeralHex(initResponse.getServerEphemeralHex());

        EntityExchangeResult<PasswordAuthenticationCompleteV1Response> apiCompleteResponse =
            webTestClient.post().uri("/password-authentication-complete-v1")
                .headers(HeadersProvider::unauthenticated)
                .body(Mono.just(completeRequest), PasswordAuthenticationCompleteV1Request.class)
                .exchange()
                .expectStatus().isOk()
                .expectBody(PasswordAuthenticationCompleteV1Response.class)
                .consumeWith(r -> {})
                .returnResult();

        PasswordAuthenticationCompleteV1Response completeResponse = apiCompleteResponse.getResponseBody();
        Assertions.assertNotNull(completeResponse);

        String serverProofHex = completeResponse.getServerProofHex();
        boolean serverProofValid = srp6Client.verifyServerEvidenceMessage(new BigInteger(serverProofHex, 16));
        Assertions.assertTrue(serverProofValid);

        BigInteger sessionKeyBigInteger = srp6Client.calculateSessionKey();
        byte[] sessionKeyBytes = BigIntegerToByteArray.convert(sessionKeyBigInteger);

        byte[] authenticationSessionIdAeadBytes =
            Base64.getDecoder().decode(completeResponse.getAuthenticationSessionIdAeadBase64());
        DiplomatiqAEAD authenticationSessionIdAead =
            DiplomatiqAEAD.fromBytes(authenticationSessionIdAeadBytes, sessionKeyBytes);
        String authenticationSessionId = new String(authenticationSessionIdAead.getPlaintext(),
            StandardCharsets.UTF_8);
        Assertions.assertEquals(32, authenticationSessionId.length());

        UserAuthentication userAuthentication =
            userAuthenticationRepository.findById(userIdentityHelper.getCurrentAuthentication(userIdentity).getId()
            ).orElseThrow();
        Assertions.assertEquals(0, userAuthentication.getUserTemporarySrpDatas().size());
        Assertions.assertEquals(1, userAuthentication.getAuthenticationSessions().size());

        AuthenticationSession authenticationSession = userAuthentication.getAuthenticationSessions().iterator()
            .next();
        Assertions.assertEquals(authenticationSessionId, authenticationSession.getId());
        Assertions.assertEquals(SessionAssuranceLevel.PasswordElevatedSession, authenticationSession
            .getAssuranceLevel());
    }
}
