package org.diplomatiq.diplomatiqbackend.methods.utils;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthenticationResetRequest;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.*;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationCompleteV1Response;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationInitV1Response;
import org.diplomatiq.diplomatiqbackend.repositories.UserAuthenticationRepository;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.diplomatiq.diplomatiqbackend.services.RegistrationService;
import org.diplomatiq.diplomatiqbackend.utils.crypto.aead.DiplomatiqAEAD;
import org.diplomatiq.diplomatiqbackend.utils.crypto.convert.BigIntegerToByteArray;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.diplomatiq.diplomatiqbackend.utils.crypto.srp.SRP6Factory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Set;

@Component
@Transactional
public class TestUtils {
    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private UserAuthenticationRepository userAuthenticationRepository;

    @Autowired
    private UserIdentityHelper userIdentityHelper;

    public String generateRandomEmail() {
        return String.format("%s@%s.%s", RandomUtils.lowercaseString(20), RandomUtils.lowercaseString(20),
            RandomUtils.lowercaseString(2));
    }

    public String registerUser() throws IOException {
        return registerUser(String.format("%s@diplomatiq.org", RandomUtils.lowercaseString(10)),
            RandomUtils.alphabeticString(10), RandomUtils.alphabeticString(10), RandomUtils.alphabeticString(10), true);
    }

    public String registerUser(boolean validated) throws IOException {
        return registerUser(String.format("%s@diplomatiq.org", RandomUtils.lowercaseString(10)),
            RandomUtils.alphabeticString(10), RandomUtils.alphabeticString(10), RandomUtils.alphabeticString(10),
            validated);
    }

    public String registerUser(String password) throws IOException {
        return registerUser(String.format("%s@diplomatiq.org", RandomUtils.lowercaseString(10)),
            RandomUtils.alphabeticString(10), RandomUtils.alphabeticString(10), password, true);
    }

    public String registerUser(String password, boolean validated) throws IOException {
        return registerUser(String.format("%s@diplomatiq.org", RandomUtils.lowercaseString(10)),
            RandomUtils.alphabeticString(10), RandomUtils.alphabeticString(10), password, validated);
    }

    public String registerUser(String emailAddress, String firstName, String lastName, String password,
                               boolean validated) throws IOException {
        byte[] srpSaltBytes = RandomUtils.bytes(32);
        String srpSaltHex = new BigInteger(1, srpSaltBytes).toString(16);

        byte[] identityBytes = emailAddress.getBytes(StandardCharsets.UTF_8);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

        SRP6VerifierGenerator srp6VerifierGenerator = SRP6Factory.getSrp6VerifierGenerator();

        BigInteger srpVerifierBigInteger = srp6VerifierGenerator.generateVerifier(srpSaltBytes, identityBytes,
            passwordBytes);
        String srpVerifierHex = srpVerifierBigInteger.toString(16);

        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Argon2_v1;

        RegisterUserV1Request registrationRequest = new RegisterUserV1Request();
        registrationRequest.setEmailAddress(emailAddress);
        registrationRequest.setFirstName(firstName);
        registrationRequest.setLastName(lastName);
        registrationRequest.setSrpSaltHex(srpSaltHex);
        registrationRequest.setSrpVerifierHex(srpVerifierHex);
        registrationRequest.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);

        registrationService.registerUserV1(registrationRequest);

        if (validated) {
            UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();
            ValidateEmailAddressV1Request emailValidationRequest = new ValidateEmailAddressV1Request();
            emailValidationRequest.setEmailValidationKey(userIdentity.getEmailValidationKey());
            authenticationService.validateEmailAddressV1(emailValidationRequest);
        }

        return emailAddress;
    }

    public String getAuthenticationSession(String emailAddress, String password) throws IOException,
        NoSuchAlgorithmException, CryptoException,
        IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException,
        NoSuchPaddingException {
        PasswordAuthenticationInitV1Request initRequest = new PasswordAuthenticationInitV1Request();
        initRequest.setEmailAddress(emailAddress);

        PasswordAuthenticationInitV1Response initResponse =
            authenticationService.passwordAuthenticationInitV1(initRequest);

        String srpSaltHex = initResponse.getSrpSaltHex();
        BigInteger srpSaltBigInteger = new BigInteger(srpSaltHex, 16);
        byte[] srpSaltBytes = BigIntegerToByteArray.convert(srpSaltBigInteger);

        byte[] identityBytes = emailAddress.getBytes(StandardCharsets.UTF_8);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

        SRP6Client srp6Client = SRP6Factory.getSrp6Client();

        String clientEphemeralHex = srp6Client.generateClientCredentials(srpSaltBytes, identityBytes,
            passwordBytes).toString(16);

        String serverEphemeralHex = initResponse.getServerEphemeralHex();
        BigInteger serverEphemeralBigInteger = new BigInteger(serverEphemeralHex, 16);
        srp6Client.calculateSecret(serverEphemeralBigInteger);

        BigInteger clientProofBigInteger = srp6Client.calculateClientEvidenceMessage();
        String clientProofHex = clientProofBigInteger.toString(16);

        PasswordAuthenticationCompleteV1Request completeRequest = new PasswordAuthenticationCompleteV1Request();
        completeRequest.setEmailAddress(emailAddress);
        completeRequest.setClientEphemeralHex(clientEphemeralHex);
        completeRequest.setClientProofHex(clientProofHex);
        completeRequest.setServerEphemeralHex(serverEphemeralHex);

        PasswordAuthenticationCompleteV1Response completeResponse =
            authenticationService.passwordAuthenticationCompleteV1(completeRequest);

        String serverProofHex = completeResponse.getServerProofHex();
        srp6Client.verifyServerEvidenceMessage(new BigInteger(serverProofHex, 16));

        BigInteger sessionKeyBigInteger = srp6Client.calculateSessionKey();
        byte[] sessionKeyBytes = BigIntegerToByteArray.convert(sessionKeyBigInteger);

        byte[] authenticationSessionIdAeadBytes =
            Base64.getDecoder().decode(completeResponse.getAuthenticationSessionIdAeadBase64());
        DiplomatiqAEAD authenticationSessionIdAead =
            DiplomatiqAEAD.fromBytes(authenticationSessionIdAeadBytes, sessionKeyBytes);
        String authenticationSessionId = new String(authenticationSessionIdAead.getPlaintext(),
            StandardCharsets.UTF_8);

        return authenticationSessionId;
    }

    public String requestPasswordReset(String emailAddress) throws IOException {
        RequestPasswordResetV1Request requestRequest = new RequestPasswordResetV1Request();
        requestRequest.setEmailAddress(emailAddress);

        authenticationService.requestPasswordResetV1(requestRequest);

        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();

        UserAuthentication userAuthentication =
            userAuthenticationRepository.findById(userIdentityHelper.getCurrentAuthentication(userIdentity).getId())
                .orElseThrow();

        Set<UserAuthenticationResetRequest> userAuthenticationResetRequests =
            userAuthentication.getUserAuthenticationResetRequests();
        UserAuthenticationResetRequest userAuthenticationResetRequest =
            userAuthenticationResetRequests.iterator().next();

        return userAuthenticationResetRequest.getRequestKey();
    }
}
