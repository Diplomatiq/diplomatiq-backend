package org.diplomatiq.diplomatiqbackend.services;

import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.diplomatiq.diplomatiqbackend.domain.models.concrete.*;
import org.diplomatiq.diplomatiqbackend.engines.PasswordStretchingEngine;
import org.diplomatiq.diplomatiqbackend.exceptions.api.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.methods.entities.PasswordAuthenticationCompleteV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.PasswordAuthenticationCompleteV1Response;
import org.diplomatiq.diplomatiqbackend.methods.entities.PasswordAuthenticationInitV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.PasswordAuthenticationInitV1Response;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.diplomatiq.diplomatiqbackend.utils.crypto.passwordstretching.AbstractPasswordStretchingAlgorithmImpl;
import org.diplomatiq.diplomatiqbackend.utils.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.*;
import org.diplomatiq.diplomatiqbackend.utils.crypto.srp.RequestBoundaryCrossingSRP6Server;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Transactional
public class AuthenticationService {
    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private PasswordStretchingEngine passwordStretchingEngine;

    public PasswordAuthenticationInitV1Response passwordAuthenticationInitV1(PasswordAuthenticationInitV1Request request) throws NoSuchAlgorithmException {
        String emailAddress = request.getEmailAddress();
        UserIdentity userIdentity =
            userIdentityRepository.findByEmailAddress(emailAddress).orElse(getDummyUserIdentity(null));

        UserAuthentication currentAuthentication = userIdentity.getCurrentAuthentication();

        byte[] srpVerifierBytes = currentAuthentication.getSrpVerifier();
        BigInteger srpVerifierBigInteger = new BigInteger(srpVerifierBytes);

        PasswordStretchingAlgorithm passwordStretchingAlgorithm =
            currentAuthentication.getPasswordStretchingAlgorithm();
        AbstractPasswordStretchingAlgorithmImpl passwordStretchingAlgorithmImpl =
            passwordStretchingEngine.getImplByAlgorithm(passwordStretchingAlgorithm);

        RequestBoundaryCrossingSRP6Server srp = new RequestBoundaryCrossingSRP6Server();
        srp.init(SRP6StandardGroups.rfc5054_8192, srpVerifierBigInteger, passwordStretchingAlgorithmImpl,
            SecureRandom.getInstanceStrong());

        BigInteger serverEphemeralBigInteger = srp.generateServerCredentials();
        String serverEphemeralBase64 = Base64.getEncoder().encodeToString(serverEphemeralBigInteger.toByteArray());

        byte[] srpSaltBytes = currentAuthentication.getSrpSalt();
        String srpSaltBase64 = Base64.getEncoder().encodeToString(srpSaltBytes);

        return new PasswordAuthenticationInitV1Response(serverEphemeralBase64, srpSaltBase64);
    }

    public PasswordAuthenticationCompleteV1Response passwordAuthenticationCompleteV1(PasswordAuthenticationCompleteV1Request request) throws NoSuchAlgorithmException {
        String emailAddress = request.getEmailAddress();

        String serverEphemeralBase64 = request.getServerEphemeralBase64();
        byte[] serverEphemeralBytes = Base64.getDecoder().decode(serverEphemeralBase64);

        UserIdentity userIdentity =
            userIdentityRepository.findByEmailAddress(emailAddress).orElse(getDummyUserIdentity(serverEphemeralBytes));

        UserAuthentication currentAuthentication = userIdentity.getCurrentAuthentication();

        byte[] srpVerifierBytes = currentAuthentication.getSrpVerifier();
        BigInteger srpVerifierBigInteger = new BigInteger(srpVerifierBytes);

        PasswordStretchingAlgorithm passwordStretchingAlgorithm =
            currentAuthentication.getPasswordStretchingAlgorithm();
        AbstractPasswordStretchingAlgorithmImpl abstractPasswordStretchingAlgorithmImpl =
            passwordStretchingEngine.getImplByAlgorithm(passwordStretchingAlgorithm);

        RequestBoundaryCrossingSRP6Server srp = new RequestBoundaryCrossingSRP6Server();
        srp.init(SRP6StandardGroups.rfc5054_8192, srpVerifierBigInteger, abstractPasswordStretchingAlgorithmImpl,
            new SecureRandom());

        Set<UserTemporarySRPLoginData> userTemporarySrpLoginData = currentAuthentication.getUserTemporarySrpLoginDatas();
        Set<ByteBuffer> savedServerEphemerals = userTemporarySrpLoginData.stream()
            .map(d -> ByteBuffer.wrap(d.getServerEphemeral()))
            .collect(Collectors.toSet());
        if (!savedServerEphemerals.contains(ByteBuffer.wrap(serverEphemeralBytes))) {
            throw new UnauthorizedException("Previous server ephemeral value not found.", null);
        }

        BigInteger serverEphemeralBigInteger = new BigInteger(serverEphemeralBytes);
        srp.setB(serverEphemeralBigInteger);

        String clientEphemeralBase64 = request.getClientEphemeralBase64();
        byte[] clientEphemeralBytes = Base64.getDecoder().decode(clientEphemeralBase64);
        BigInteger clientEphemeralBigInteger = new BigInteger(clientEphemeralBytes);

        try {
            srp.calculateSecret(clientEphemeralBigInteger);
        } catch (Exception ex) {
            throw new UnauthorizedException("SRP secret could not be calculated.", ex);
        }

        String clientProofHex = request.getClientProofBase64();
        BigInteger clientProofBigInteger = new BigInteger(clientProofHex, 16);

        boolean clientProofVerified;
        try {
            clientProofVerified = srp.verifyClientEvidenceMessage(clientProofBigInteger);
        } catch (Exception ex) {
            throw new UnauthorizedException("Crypto error during client proof verification.", ex);
        }

        if (!clientProofVerified) {
            throw new UnauthorizedException("Client proof could not be verified.", null);
        }

        BigInteger serverProofBigInteger;
        try {
            serverProofBigInteger = srp.calculateServerEvidenceMessage();
        } catch (Exception ex) {
            throw new UnauthorizedException("Crypto error during server proof calculation.", ex);
        }

        BigInteger authenticationSessionKeyBigInteger;
        try {
            authenticationSessionKeyBigInteger = srp.calculateSessionKey();
        } catch (Exception ex) {
            throw new UnauthorizedException("Device key could not be calculated.", ex);
        }

        AuthenticationSession authenticationSession = new AuthenticationSession();

        String authenticationSessionId = AuthenticationSessionIdGenerator.generate();
        authenticationSession.setAuthenticationSessionId(authenticationSessionId);

        byte[] authenticationSessionKeyBytes = authenticationSessionKeyBigInteger.toByteArray();
        authenticationSession.setAuthenticationSessionKey(authenticationSessionKeyBytes);

        Set<AuthenticationSession> authenticationSessions =
            Optional.ofNullable(currentAuthentication.getAuthenticationSessions()).orElse(new HashSet<>());
        authenticationSessions.add(authenticationSession);
        currentAuthentication.setAuthenticationSessions(authenticationSessions);

        userIdentityRepository.save(userIdentity);

        String serverProofHex = serverProofBigInteger.toString(16);

        return new PasswordAuthenticationCompleteV1Response(serverProofHex, authenticationSessionId);
    }

    public String validateAndDecryptEncryptedSessionId(String encryptedSessionId, String deviceId) {
        if (encryptedSessionId == null) {
            throw new IllegalArgumentException("encryptedSessionId must not be null");
        }

        if (encryptedSessionId.equals("")) {
            throw new IllegalArgumentException("encryptedSessionId must not be empty");
        }

        if (deviceId == null) {
            throw new IllegalArgumentException("deviceId must not be null");
        }

        if (deviceId.equals("")) {
            throw new IllegalArgumentException("deviceId must not be empty");
        }

        String decryptedSessionId = "decryptedSessionId";

        return decryptedSessionId;
    }

    public UserIdentity getUserBySessionId(String sessionId) throws NoSuchAlgorithmException {
        if (sessionId == null) {
            throw new IllegalArgumentException("sessionId must not be null");
        }

        if (sessionId.equals("")) {
            throw new IllegalArgumentException("sessionId must not be empty");
        }

        return getDummyUserIdentity(null);
    }

    public byte[] getDeviceKeyByDeviceId(String deviceId) {
        if (deviceId == null) {
            throw new IllegalArgumentException("deviceId must not be null");
        }

        if (deviceId.equals("")) {
            throw new IllegalArgumentException("deviceId must not be empty");
        }

        return new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    }

    private UserIdentity getDummyUserIdentity(byte[] serverEphemeralBytes) throws NoSuchAlgorithmException {
        final String emailAddress = "samsepi0l@diplomatiq.org";

        PasswordStretchingAlgorithm passwordStretchingAlgorithm = passwordStretchingEngine.getLatestAlgorithm();
        AbstractPasswordStretchingAlgorithmImpl passwordStretchingAlgorithmImpl =
            passwordStretchingEngine.getImplByAlgorithm(passwordStretchingAlgorithm);

        byte[] srpSalt = RandomUtils.strongBytes(32);

        SRP6VerifierGenerator srp6VerifierGenerator = new SRP6VerifierGenerator();
        srp6VerifierGenerator.init(SRP6StandardGroups.rfc5054_8192, passwordStretchingAlgorithmImpl);

        byte[] emailAddressBytes = emailAddress.getBytes(StandardCharsets.UTF_8);

        String password = RandomUtils.alphanumericString(32);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

        BigInteger srpVerifierBigInteger = srp6VerifierGenerator.generateVerifier(srpSalt, emailAddressBytes,
            passwordBytes);
        byte[] srpVerifierBytes = srpVerifierBigInteger.toByteArray();

        BigInteger serverEphemeralBigInt = serverEphemeralBytes != null
            ? new BigInteger(serverEphemeralBytes)
            : new BigInteger("5");

        UserIdentity userIdentity = new UserIdentity();

        userIdentity.setEmailAddress("samsepi0l@diplomatiq.org");
        userIdentity.setFirstName("Sam");
        userIdentity.setLastName("Sepiol");
        userIdentity.setValidated(true);

        UserTemporarySRPLoginData userTemporarySRPLoginData = new UserTemporarySRPLoginData();
        userTemporarySRPLoginData.setServerEphemeral(serverEphemeralBigInt.toByteArray());

        UserAuthentication authentication = new UserAuthentication();
        authentication.setVersion(1L);
        authentication.setSrpSalt(srpSalt);
        authentication.setSrpVerifier(srpVerifierBytes);
        authentication.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);
        authentication.setUserTemporarySrpLoginDatas(Set.of(userTemporarySRPLoginData));
        userIdentity.setAuthentications(Set.of(authentication));

        UserDevice device = new UserDevice();
        device.setDeviceId(DeviceIdGenerator.generate());
        device.setDeviceKey(DeviceKeyGenerator.generate());
        userIdentity.setDevices(Set.of(device));

        UserDeviceContainer deviceContainer = new UserDeviceContainer();
        deviceContainer.setDeviceContainerId(DeviceContainerIdGenerator.generate());
        deviceContainer.setDeviceContainerKey(DeviceContainerKeyGenerator.generate());
        device.setUserDeviceContainer(deviceContainer);

        return userIdentity;
    }
}
