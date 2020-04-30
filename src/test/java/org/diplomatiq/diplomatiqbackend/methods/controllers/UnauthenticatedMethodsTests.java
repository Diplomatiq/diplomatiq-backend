//package org.diplomatiq.diplomatiqbackend.methods.controllers;
//
//import com.sendgrid.Request;
//import com.sendgrid.SendGrid;
//import org.bouncycastle.crypto.CryptoException;
//import org.bouncycastle.crypto.agreement.srp.SRP6Client;
//import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
//import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.*;
//import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserDeviceHelper;
//import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
//import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
//import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiError;
//import org.diplomatiq.diplomatiqbackend.exceptions.internal.UnauthorizedException;
//import org.diplomatiq.diplomatiqbackend.methods.attributes.SessionAssuranceLevel;
//import org.diplomatiq.diplomatiqbackend.methods.entities.requests.*;
//import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationCompleteV1Response;
//import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationInitV1Response;
//import org.diplomatiq.diplomatiqbackend.methods.utils.HeadersProvider;
//import org.diplomatiq.diplomatiqbackend.methods.utils.TestUtils;
//import org.diplomatiq.diplomatiqbackend.repositories.UserAuthenticationRepository;
//import org.diplomatiq.diplomatiqbackend.repositories.UserDeviceRepository;
//import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
//import org.diplomatiq.diplomatiqbackend.repositories.UserTemporarySRPDataRepository;
//import org.diplomatiq.diplomatiqbackend.utils.crypto.aead.DiplomatiqAEAD;
//import org.diplomatiq.diplomatiqbackend.utils.crypto.convert.BigIntegerToByteArray;
//import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
//import org.diplomatiq.diplomatiqbackend.utils.crypto.srp.SRP6Factory;
//import org.junit.jupiter.api.Assertions;
//import org.junit.jupiter.api.Test;
//import org.mockito.Mockito;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//import org.springframework.http.MediaType;
//import org.springframework.test.context.ActiveProfiles;
//import org.springframework.test.web.reactive.server.EntityExchangeResult;
//import org.springframework.test.web.reactive.server.WebTestClient;
//import reactor.core.publisher.Mono;
//
//import javax.crypto.BadPaddingException;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import java.io.IOException;
//import java.math.BigInteger;
//import java.nio.charset.StandardCharsets;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.util.Base64;
//import java.util.Set;
//
//@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
//@ActiveProfiles("testing")
//public class UnauthenticatedMethodsTests {
//    @Autowired
//    private WebTestClient webTestClient;
//
//    @Autowired
//    private UserIdentityRepository userIdentityRepository;
//
//    @Autowired
//    private UserAuthenticationRepository userAuthenticationRepository;
//
//    @Autowired
//    private UserTemporarySRPDataRepository userTemporarySRPDataRepository;
//
//    @Autowired
//    private UserDeviceRepository userDeviceRepository;
//
//    @Autowired
//    private UserIdentityHelper userIdentityHelper;
//
//    @Autowired
//    private UserDeviceHelper userDeviceHelper;
//
//    @Autowired
//    private TestUtils testUtils;
//
//    @MockBean
//    SendGrid sendGridApiClient;
//
//    @Test
//    public void registerUserV1_shouldRegisterUser() throws IOException {
//        String emailAddress = "samsepi0l@diplomatiq.org";
//        String firstName = "Sam";
//        String lastName = "Sepiol";
//        String srpSaltHex = new BigInteger(1, RandomUtils.bytes(32)).toString(16);
//        String srpVerifierHex = new BigInteger(1, RandomUtils.bytes(1024)).toString(16);
//        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Argon2_v1;
//
//        RegisterUserV1Request request = new RegisterUserV1Request();
//        request.setEmailAddress(emailAddress);
//        request.setFirstName(firstName);
//        request.setLastName(lastName);
//        request.setSrpSaltHex(srpSaltHex);
//        request.setSrpVerifierHex(srpVerifierHex);
//        request.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);
//
//        webTestClient.post().uri("/register-user-v1")
//            .headers(HeadersProvider::unauthenticated)
//            .body(Mono.just(request), RegisterUserV1Request.class)
//            .exchange()
//            .expectStatus().isOk()
//            .expectBody().isEmpty();
//
//        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();
//        Assertions.assertEquals(emailAddress, userIdentity.getEmailAddress());
//        Assertions.assertEquals(firstName, userIdentity.getFirstName());
//        Assertions.assertEquals(lastName, userIdentity.getLastName());
//        Assertions.assertFalse(userIdentity.isEmailValidated());
//        Assertions.assertEquals(150, userIdentity.getEmailValidationKey().length());
//
//        Set<UserAuthentication> userAuthentications = userIdentity.getAuthentications();
//        Assertions.assertEquals(1, userAuthentications.size());
//
//        UserAuthentication userAuthentication = userIdentityHelper.getCurrentAuthentication(userIdentity);
//        Assertions.assertEquals(srpSaltHex, userAuthentication.getSrpSaltHex());
//        Assertions.assertEquals(srpVerifierHex, userAuthentication.getSrpVerifierHex());
//        Assertions.assertEquals(PasswordStretchingAlgorithm.Argon2_v1,
//            userAuthentication.getPasswordStretchingAlgorithm());
//
//        Assertions.assertEquals(0, userIdentity.getDevices().size());
//
//        Mockito.verify(sendGridApiClient, Mockito.times(1)).api(Mockito.any(Request.class));
//    }
//
//    @Test
//    public void registerUserV1_shouldNotThrowIfUserAlreadyExists() throws IOException {
//        String emailAddress = testUtils.registerUser();
//
//        boolean registeredUserExists = userIdentityRepository.existsByEmailAddress(emailAddress);
//        Assertions.assertTrue(registeredUserExists);
//
//        String firstName = "Sam";
//        String lastName = "Sepiol";
//        String srpSaltHex = new BigInteger(1, RandomUtils.bytes(32)).toString(16);
//        String srpVerifierHex = new BigInteger(1, RandomUtils.bytes(1024)).toString(16);
//        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Argon2_v1;
//
//        RegisterUserV1Request request = new RegisterUserV1Request();
//        request.setEmailAddress(emailAddress);
//        request.setFirstName(firstName);
//        request.setLastName(lastName);
//        request.setSrpSaltHex(srpSaltHex);
//        request.setSrpVerifierHex(srpVerifierHex);
//        request.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);
//
//        webTestClient.post().uri("/register-user-v1")
//            .headers(HeadersProvider::unauthenticated)
//            .body(Mono.just(request), RegisterUserV1Request.class)
//            .exchange()
//            .expectStatus().isOk()
//            .expectBody().isEmpty();
//
//        Mockito.verify(sendGridApiClient, Mockito.times(1)).api(Mockito.any(Request.class));
//    }
//
//    @Test
//    public void passwordAuthenticationInitV1_shouldInitPasswordAuthentication() throws IOException {
//        String password = "secret";
//        String emailAddress = testUtils.registerUser(password);
//        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();
//        UserAuthentication userAuthentication =
//            userAuthenticationRepository.findById(userIdentityHelper.getCurrentAuthentication(userIdentity).getId())
//                .orElseThrow();
//
//        Assertions.assertEquals(0, userAuthentication.getUserTemporarySrpDatas().size());
//
//        PasswordAuthenticationInitV1Request request = new PasswordAuthenticationInitV1Request();
//        request.setEmailAddress(userIdentity.getEmailAddress());
//
//        EntityExchangeResult<PasswordAuthenticationInitV1Response> apiResponse =
//            webTestClient.post().uri("/password-authentication-init-v1")
//                .headers(HeadersProvider::unauthenticated)
//                .body(Mono.just(request), PasswordAuthenticationInitV1Request.class)
//                .exchange()
//                .expectStatus().isOk()
//                .expectBody(PasswordAuthenticationInitV1Response.class)
//                .returnResult();
//
//        PasswordAuthenticationInitV1Response response = apiResponse.getResponseBody();
//        Assertions.assertNotNull(response);
//
//        Assertions.assertEquals(userAuthentication.getSrpSaltHex(), response.getSrpSaltHex());
//        Assertions.assertEquals(userAuthentication.getPasswordStretchingAlgorithm(),
//            response.getPasswordStretchingAlgorithm());
//
//        UserAuthentication freshUserAuthentication =
//            userAuthenticationRepository.findById(userIdentityHelper.getCurrentAuthentication(userIdentity).getId())
//                .orElseThrow();
//
//        Assertions.assertEquals(1, freshUserAuthentication.getUserTemporarySrpDatas().size());
//        UserTemporarySRPData userTemporarySRPData = freshUserAuthentication.getUserTemporarySrpDatas().iterator().next();
//        Assertions.assertEquals(response.getServerEphemeralHex(), userTemporarySRPData.getServerEphemeralHex());
//    }
//
//    @Test
//    public void passwordAuthenticationInitV1_shouldNotThrowIfUserNotExists() {
//        PasswordAuthenticationInitV1Request request = new PasswordAuthenticationInitV1Request();
//        request.setEmailAddress(testUtils.generateRandomEmail());
//
//        EntityExchangeResult<PasswordAuthenticationInitV1Response> apiResponse =
//            webTestClient.post().uri("/password-authentication-init-v1")
//                .headers(HeadersProvider::unauthenticated)
//                .body(Mono.just(request), PasswordAuthenticationInitV1Request.class)
//                .exchange()
//                .expectStatus().isOk()
//                .expectBody(PasswordAuthenticationInitV1Response.class)
//                .returnResult();
//
//        PasswordAuthenticationInitV1Response response = apiResponse.getResponseBody();
//        Assertions.assertNotNull(response);
//    }
//
//    @Test
//    public void passwordAuthenticationCompleteV1_shouldCreateAuthenticationSession() throws IOException,
//        CryptoException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
//        IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
//        String password = "secret";
//        String emailAddress = testUtils.registerUser(password);
//        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();
//
//        PasswordAuthenticationInitV1Request initRequest = new PasswordAuthenticationInitV1Request();
//        initRequest.setEmailAddress(emailAddress);
//
//        EntityExchangeResult<PasswordAuthenticationInitV1Response> initApiResponse =
//            webTestClient.post().uri("/password-authentication-init-v1")
//                .headers(HeadersProvider::unauthenticated)
//                .body(Mono.just(initRequest), PasswordAuthenticationInitV1Request.class)
//                .exchange()
//                .expectStatus().isOk()
//                .expectBody(PasswordAuthenticationInitV1Response.class)
//                .returnResult();
//
//        PasswordAuthenticationInitV1Response initResponse = initApiResponse.getResponseBody();
//        Assertions.assertNotNull(initResponse);
//
//        String srpSaltHex = initResponse.getSrpSaltHex();
//        BigInteger srpSaltBigInteger = new BigInteger(srpSaltHex, 16);
//        byte[] srpSaltBytes = BigIntegerToByteArray.convert(srpSaltBigInteger);
//
//        byte[] identityBytes = emailAddress.getBytes(StandardCharsets.UTF_8);
//        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
//
//        SRP6Client srp6Client = SRP6Factory.getSrp6Client();
//
//        String clientEphemeralHex = srp6Client.generateClientCredentials(srpSaltBytes, identityBytes,
//            passwordBytes).toString(16);
//
//        String serverEphemeralHex = initResponse.getServerEphemeralHex();
//        BigInteger serverEphemeralBigInteger = new BigInteger(serverEphemeralHex, 16);
//        srp6Client.calculateSecret(serverEphemeralBigInteger);
//
//        BigInteger clientProofBigInteger = srp6Client.calculateClientEvidenceMessage();
//        String clientProofHex = clientProofBigInteger.toString(16);
//
//        PasswordAuthenticationCompleteV1Request completeRequest = new PasswordAuthenticationCompleteV1Request();
//        completeRequest.setEmailAddress(emailAddress);
//        completeRequest.setClientEphemeralHex(clientEphemeralHex);
//        completeRequest.setClientProofHex(clientProofHex);
//        completeRequest.setServerEphemeralHex(serverEphemeralHex);
//
//        EntityExchangeResult<PasswordAuthenticationCompleteV1Response> apiCompleteResponse =
//            webTestClient.post().uri("/password-authentication-complete-v1")
//                .headers(HeadersProvider::unauthenticated)
//                .body(Mono.just(completeRequest), PasswordAuthenticationCompleteV1Request.class)
//                .exchange()
//                .expectStatus().isOk()
//                .expectBody(PasswordAuthenticationCompleteV1Response.class)
//                .returnResult();
//
//        PasswordAuthenticationCompleteV1Response completeResponse = apiCompleteResponse.getResponseBody();
//        Assertions.assertNotNull(completeResponse);
//
//        String serverProofHex = completeResponse.getServerProofHex();
//        boolean serverProofValid = srp6Client.verifyServerEvidenceMessage(new BigInteger(serverProofHex, 16));
//        Assertions.assertTrue(serverProofValid);
//
//        BigInteger sessionKeyBigInteger = srp6Client.calculateSessionKey();
//        byte[] sessionKeyBytes = BigIntegerToByteArray.convert(sessionKeyBigInteger);
//
//        byte[] authenticationSessionIdAeadBytes =
//            Base64.getDecoder().decode(completeResponse.getAuthenticationSessionIdAeadBase64());
//        DiplomatiqAEAD authenticationSessionIdAead =
//            DiplomatiqAEAD.fromBytes(authenticationSessionIdAeadBytes, sessionKeyBytes);
//        String authenticationSessionId = new String(authenticationSessionIdAead.getPlaintext(),
//            StandardCharsets.UTF_8);
//        Assertions.assertEquals(32, authenticationSessionId.length());
//
//        UserAuthentication userAuthentication =
//            userAuthenticationRepository.findById(userIdentityHelper.getCurrentAuthentication(userIdentity).getId())
//                .orElseThrow();
//        Assertions.assertEquals(0, userAuthentication.getUserTemporarySrpDatas().size());
//        Assertions.assertEquals(1, userAuthentication.getAuthenticationSessions().size());
//
//        AuthenticationSession authenticationSession = userAuthentication.getAuthenticationSessions().iterator()
//            .next();
//        Assertions.assertEquals(authenticationSessionId, authenticationSession.getId());
//        Assertions.assertEquals(SessionAssuranceLevel.PasswordElevatedSession, authenticationSession
//            .getAssuranceLevel());
//    }
//
//    @Test
//    public void passwordAuthenticationCompleteV1_shouldNotCreateAuthenticationSessionForWrongPassword() throws
//        IOException, CryptoException {
//        String password = "secret";
//        String notPassword = "wrongpassword";
//        String emailAddress = testUtils.registerUser(password);
//        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();
//
//        PasswordAuthenticationInitV1Request initRequest = new PasswordAuthenticationInitV1Request();
//        initRequest.setEmailAddress(userIdentity.getEmailAddress());
//
//        EntityExchangeResult<PasswordAuthenticationInitV1Response> initApiResponse =
//            webTestClient.post().uri("/password-authentication-init-v1")
//                .headers(HeadersProvider::unauthenticated)
//                .body(Mono.just(initRequest), PasswordAuthenticationInitV1Request.class)
//                .exchange()
//                .expectStatus().isOk()
//                .expectBody(PasswordAuthenticationInitV1Response.class)
//                .returnResult();
//
//        PasswordAuthenticationInitV1Response initResponse = initApiResponse.getResponseBody();
//        Assertions.assertNotNull(initResponse);
//
//        String srpSaltHex = initResponse.getSrpSaltHex();
//        BigInteger srpSaltBigInteger = new BigInteger(srpSaltHex, 16);
//        byte[] srpSaltBytes = BigIntegerToByteArray.convert(srpSaltBigInteger);
//
//        byte[] identityBytes = userIdentity.getEmailAddress().getBytes(StandardCharsets.UTF_8);
//        byte[] passwordBytes = notPassword.getBytes(StandardCharsets.UTF_8);
//
//        SRP6Client srp6Client = SRP6Factory.getSrp6Client();
//
//        String clientEphemeralHex = srp6Client.generateClientCredentials(srpSaltBytes, identityBytes,
//            passwordBytes).toString(16);
//
//        String serverEphemeralHex = initResponse.getServerEphemeralHex();
//        BigInteger serverEphemeralBigInteger = new BigInteger(serverEphemeralHex, 16);
//        srp6Client.calculateSecret(serverEphemeralBigInteger);
//
//        BigInteger clientProofBigInteger = srp6Client.calculateClientEvidenceMessage();
//        String clientProofHex = clientProofBigInteger.toString(16);
//
//        PasswordAuthenticationCompleteV1Request completeRequest = new PasswordAuthenticationCompleteV1Request();
//        completeRequest.setEmailAddress(userIdentity.getEmailAddress());
//        completeRequest.setClientEphemeralHex(clientEphemeralHex);
//        completeRequest.setClientProofHex(clientProofHex);
//        completeRequest.setServerEphemeralHex(initResponse.getServerEphemeralHex());
//
//        EntityExchangeResult<DiplomatiqApiError> apiCompleteResponse =
//            webTestClient.post().uri("/password-authentication-complete-v1")
//                .headers(HeadersProvider::unauthenticated)
//                .body(Mono.just(completeRequest), PasswordAuthenticationCompleteV1Request.class)
//                .exchange()
//                .expectStatus().isBadRequest()
//                .expectBody(DiplomatiqApiError.class)
//                .returnResult();
//
//        DiplomatiqApiError apiError = apiCompleteResponse.getResponseBody();
//        Assertions.assertNotNull(apiError);
//        Assertions.assertEquals(apiError.getErrorCode(), DiplomatiqApiError.DiplomatiqApiErrorCode.Unauthorized);
//    }
//
//    @Test
//    public void passwordAuthenticationCompleteV1_shouldNotCreateAuthenticationSessionForNonExistingAccount() throws
//        CryptoException {
//        String emailAddress = testUtils.generateRandomEmail();
//        String password = "secret";
//
//        PasswordAuthenticationInitV1Request initRequest = new PasswordAuthenticationInitV1Request();
//        initRequest.setEmailAddress(emailAddress);
//
//        EntityExchangeResult<PasswordAuthenticationInitV1Response> initApiResponse =
//            webTestClient.post().uri("/password-authentication-init-v1")
//                .headers(HeadersProvider::unauthenticated)
//                .body(Mono.just(initRequest), PasswordAuthenticationInitV1Request.class)
//                .exchange()
//                .expectStatus().isOk()
//                .expectBody(PasswordAuthenticationInitV1Response.class)
//                .returnResult();
//
//        PasswordAuthenticationInitV1Response initResponse = initApiResponse.getResponseBody();
//        Assertions.assertNotNull(initResponse);
//
//        String srpSaltHex = initResponse.getSrpSaltHex();
//        BigInteger srpSaltBigInteger = new BigInteger(srpSaltHex, 16);
//        byte[] srpSaltBytes = BigIntegerToByteArray.convert(srpSaltBigInteger);
//
//        byte[] identityBytes = emailAddress.getBytes(StandardCharsets.UTF_8);
//        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
//
//        SRP6Client srp6Client = SRP6Factory.getSrp6Client();
//
//        String clientEphemeralHex = srp6Client.generateClientCredentials(srpSaltBytes, identityBytes,
//            passwordBytes).toString(16);
//
//        String serverEphemeralHex = initResponse.getServerEphemeralHex();
//        BigInteger serverEphemeralBigInteger = new BigInteger(serverEphemeralHex, 16);
//        srp6Client.calculateSecret(serverEphemeralBigInteger);
//
//        BigInteger clientProofBigInteger = srp6Client.calculateClientEvidenceMessage();
//        String clientProofHex = clientProofBigInteger.toString(16);
//
//        PasswordAuthenticationCompleteV1Request completeRequest = new PasswordAuthenticationCompleteV1Request();
//        completeRequest.setEmailAddress(emailAddress);
//        completeRequest.setClientEphemeralHex(clientEphemeralHex);
//        completeRequest.setClientProofHex(clientProofHex);
//        completeRequest.setServerEphemeralHex(initResponse.getServerEphemeralHex());
//
//        EntityExchangeResult<DiplomatiqApiError> apiCompleteResponse =
//            webTestClient.post().uri("/password-authentication-complete-v1")
//                .headers(HeadersProvider::unauthenticated)
//                .body(Mono.just(completeRequest), PasswordAuthenticationCompleteV1Request.class)
//                .exchange()
//                .expectStatus().isBadRequest()
//                .expectBody(DiplomatiqApiError.class)
//                .returnResult();
//
//        DiplomatiqApiError apiError = apiCompleteResponse.getResponseBody();
//        Assertions.assertNotNull(apiError);
//        Assertions.assertEquals(apiError.getErrorCode(), DiplomatiqApiError.DiplomatiqApiErrorCode.Unauthorized);
//    }
//
//    @Test
//    public void requestPasswordResetV1_shouldSendEmailToExistingUser() throws IOException {
//        String emailAddress = testUtils.registerUser();
//
//        RequestPasswordResetV1Request request = new RequestPasswordResetV1Request();
//        request.setEmailAddress(emailAddress);
//
//        webTestClient.post().uri("/request-password-reset-v1")
//            .headers(HeadersProvider::unauthenticated)
//            .body(Mono.just(request), RequestPasswordResetV1Request.class)
//            .exchange()
//            .expectStatus().isOk()
//            .expectBody().isEmpty();
//
//        Mockito.verify(sendGridApiClient, Mockito.times(2)).api(Mockito.any(Request.class));
//    }
//
//    @Test
//    public void requestPasswordResetV1_shouldNotSendEmailToNonExistingUserButSucceed() throws IOException {
//        String emailAddress = testUtils.generateRandomEmail();
//
//        RequestPasswordResetV1Request request = new RequestPasswordResetV1Request();
//        request.setEmailAddress(emailAddress);
//
//        webTestClient.post().uri("/request-password-reset-v1")
//            .headers(HeadersProvider::unauthenticated)
//            .body(Mono.just(request), RequestPasswordResetV1Request.class)
//            .exchange()
//            .expectStatus().isOk()
//            .expectBody().isEmpty();
//
//        Mockito.verify(sendGridApiClient, Mockito.never()).api(Mockito.any(Request.class));
//    }
//
//    @Test
//    public void resetPasswordV1_shouldResetPassword() throws IOException {
//        String oldPassword = "secret";
//        String newPassword = "newsecret";
//        String emailAddress = testUtils.registerUser(oldPassword);
//        String passwordResetKey = testUtils.requestPasswordReset(emailAddress);
//
//        SRP6VerifierGenerator srp6VerifierGenerator = SRP6Factory.getSrp6VerifierGenerator();
//
//        byte[] saltBytes = RandomUtils.bytes(32);
//        String srpSaltHex = new BigInteger(1, saltBytes).toString(16);
//
//        byte[] identityBytes = emailAddress.getBytes(StandardCharsets.UTF_8);
//        byte[] passwordBytes = newPassword.getBytes(StandardCharsets.UTF_8);
//
//        String srpVerifierHex =
//            srp6VerifierGenerator.generateVerifier(saltBytes, identityBytes, passwordBytes).toString(16);
//
//        ResetPasswordV1Request request = new ResetPasswordV1Request();
//        request.setPasswordResetKey(passwordResetKey);
//        request.setSrpSaltHex(srpSaltHex);
//        request.setSrpVerifierHex(srpVerifierHex);
//        request.setPasswordStretchingAlgorithm(PasswordStretchingAlgorithm.Argon2_v1);
//
//        webTestClient.post().uri("/reset-password-v1")
//            .headers(HeadersProvider::unauthenticated)
//            .body(Mono.just(request), ResetPasswordV1Request.class)
//            .exchange()
//            .expectStatus().isOk()
//            .expectBody().isEmpty();
//
//        Assertions.assertDoesNotThrow(() -> testUtils.getAuthenticationSession(emailAddress, newPassword));
//        Assertions.assertThrows(UnauthorizedException.class, () -> testUtils.getAuthenticationSession(emailAddress,
//            oldPassword));
//    }
//
//    @Test
//    public void validateEmailAddressV1_shouldValidateEmailAddress() throws IOException {
//        String emailAddress = testUtils.registerUser(false);
//        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();
//        Assertions.assertFalse(userIdentity.isEmailValidated());
//
//        String emailValidationKey = userIdentity.getEmailValidationKey();
//        Assertions.assertEquals(150, emailValidationKey.length());
//
//        ValidateEmailAddressV1Request request = new ValidateEmailAddressV1Request();
//        request.setEmailValidationKey(emailValidationKey);
//
//        webTestClient.post().uri("/validate-email-address-v1")
//            .headers(HeadersProvider::unauthenticated)
//            .body(Mono.just(request), ResetPasswordV1Request.class)
//            .exchange()
//            .expectStatus().isOk()
//            .expectBody().isEmpty();
//
//        UserIdentity freshUserIdentity = userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();
//        Assertions.assertTrue(freshUserIdentity.isEmailValidated());
//    }
//
//    @Test
//    public void validateEmailAddressV1_shouldNotThrowForNotExistingKey() {
//        String emailValidationKey = RandomUtils.alphanumericString(150);
//        Assertions.assertTrue(userIdentityRepository.findByEmailValidationKey(emailValidationKey).isEmpty());
//
//        ValidateEmailAddressV1Request request = new ValidateEmailAddressV1Request();
//        request.setEmailValidationKey(emailValidationKey);
//
//        webTestClient.post().uri("/validate-email-address-v1")
//            .headers(HeadersProvider::unauthenticated)
//            .body(Mono.just(request), ResetPasswordV1Request.class)
//            .exchange()
//            .expectStatus().isOk()
//            .expectBody().isEmpty();
//    }
//
//    @Test
//    public void getDeviceContainerKeyV1_shouldReturnDeviceContainerKey() {
//        UserDevice userDevice = userDeviceHelper.create();
//        userDeviceRepository.save(userDevice);
//
//        EntityExchangeResult<byte[]> apiResponse = webTestClient.get()
//            .uri(uriBuilder -> uriBuilder
//                .path("/get-device-container-key-v1")
//                .queryParam("deviceId", userDevice.getId()).build())
//            .headers(HeadersProvider::unauthenticated)
//            .exchange()
//            .expectStatus().isOk()
//            .expectHeader().contentType(MediaType.APPLICATION_OCTET_STREAM)
//            .expectBody().returnResult();
//
//        byte[] deviceContainerKey = apiResponse.getResponseBody();
//        Assertions.assertNotNull(deviceContainerKey);
//        Assertions.assertArrayEquals(userDevice.getDeviceContainerKey(), deviceContainerKey);
//    }
//
//    @Test
//    public void getDeviceContainerKeyV1_shouldNotThrowOnUnknownId() {
//        UserDevice nonExistingDevice = userDeviceHelper.create();
//
//        EntityExchangeResult<byte[]> apiResponse = webTestClient.get()
//            .uri(uriBuilder -> uriBuilder
//                .path("/get-device-container-key-v1")
//                .queryParam("deviceId", nonExistingDevice.getId()).build())
//            .headers(HeadersProvider::unauthenticated)
//            .exchange()
//            .expectStatus().isOk()
//            .expectHeader().contentType(MediaType.APPLICATION_OCTET_STREAM)
//            .expectBody().returnResult();
//
//        byte[] deviceContainerKey = apiResponse.getResponseBody();
//        Assertions.assertNotNull(deviceContainerKey);
//    }
//}
