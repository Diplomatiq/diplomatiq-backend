package org.diplomatiq.diplomatiqbackend.services;

import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.AuthenticationSession;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserTemporarySRPLoginData;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.AuthenticationSessionHelper;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.AbstractPasswordStretchingAlgorithmImpl;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingEngine;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.PasswordAuthenticationCompleteV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.PasswordAuthenticationInitV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationCompleteV1Response;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationInitV1Response;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.diplomatiq.diplomatiqbackend.utils.crypto.srp.RequestBoundaryCrossingSRP6Server;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
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

    @Autowired
    private UserIdentityHelper userIdentityHelper;

    public byte[] getDeviceContainerKeyV1(String deviceContainerKey) {
        return new byte[]{};
    }

    public PasswordAuthenticationInitV1Response passwordAuthenticationInitV1(PasswordAuthenticationInitV1Request request) {
        String emailAddress = request.getEmailAddress();
        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress)
            .orElse(userIdentityHelper.dummyUserIdentity(null));

        UserAuthentication currentAuthentication = userIdentity.getCurrentAuthentication();

        byte[] srpVerifierBytes = currentAuthentication.getSrpVerifier();
        BigInteger srpVerifierBigInteger = new BigInteger(srpVerifierBytes);

        PasswordStretchingAlgorithm passwordStretchingAlgorithm =
            currentAuthentication.getPasswordStretchingAlgorithm();
        AbstractPasswordStretchingAlgorithmImpl passwordStretchingAlgorithmImpl =
            passwordStretchingEngine.getImplByAlgorithm(passwordStretchingAlgorithm);

        RequestBoundaryCrossingSRP6Server srp = new RequestBoundaryCrossingSRP6Server();
        srp.init(SRP6StandardGroups.rfc5054_8192, srpVerifierBigInteger, passwordStretchingAlgorithmImpl,
            RandomUtils.getStrongSecureRandom());

        BigInteger serverEphemeralBigInteger = srp.generateServerCredentials();
        String serverEphemeralBase64 = Base64.getEncoder().encodeToString(serverEphemeralBigInteger.toByteArray());

        byte[] srpSaltBytes = currentAuthentication.getSrpSalt();
        String srpSaltBase64 = Base64.getEncoder().encodeToString(srpSaltBytes);

        return new PasswordAuthenticationInitV1Response(serverEphemeralBase64, srpSaltBase64);
    }

    public PasswordAuthenticationCompleteV1Response passwordAuthenticationCompleteV1(PasswordAuthenticationCompleteV1Request request) throws NoSuchAlgorithmException {
        String emailAddress = request.getEmailAddress();

        byte[] serverEphemeralBytes;
        try {
            String serverEphemeralBase64 = request.getServerEphemeralBase64();
            serverEphemeralBytes = Base64.getDecoder().decode(serverEphemeralBase64);
        } catch (Exception ex) {
            throw new UnauthorizedException("Could not decode server ephemeral.", ex);
        }

        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress)
            .orElse(userIdentityHelper.dummyUserIdentity(serverEphemeralBytes));

        UserAuthentication currentAuthentication = userIdentity.getCurrentAuthentication();

        byte[] srpVerifierBytes = currentAuthentication.getSrpVerifier();
        BigInteger srpVerifierBigInteger = new BigInteger(srpVerifierBytes);

        PasswordStretchingAlgorithm passwordStretchingAlgorithm =
            currentAuthentication.getPasswordStretchingAlgorithm();
        AbstractPasswordStretchingAlgorithmImpl abstractPasswordStretchingAlgorithmImpl =
            passwordStretchingEngine.getImplByAlgorithm(passwordStretchingAlgorithm);

        RequestBoundaryCrossingSRP6Server srp = new RequestBoundaryCrossingSRP6Server();
        srp.init(SRP6StandardGroups.rfc5054_8192, srpVerifierBigInteger, abstractPasswordStretchingAlgorithmImpl,
            RandomUtils.getStrongSecureRandom());

        Set<UserTemporarySRPLoginData> userTemporarySrpLoginData =
            currentAuthentication.getUserTemporarySrpLoginDatas();
        Set<ByteBuffer> savedServerEphemerals = userTemporarySrpLoginData.stream()
            .map(d -> ByteBuffer.wrap(d.getServerEphemeral()))
            .collect(Collectors.toSet());
        if (!savedServerEphemerals.contains(ByteBuffer.wrap(serverEphemeralBytes))) {
            throw new UnauthorizedException("Previous server ephemeral value not found.", null);
        }

        BigInteger serverEphemeralBigInteger = new BigInteger(serverEphemeralBytes);
        srp.setB(serverEphemeralBigInteger);

        BigInteger clientEphemeralBigInteger;
        try {
            String clientEphemeralBase64 = request.getClientEphemeralBase64();
            byte[] clientEphemeralBytes = Base64.getDecoder().decode(clientEphemeralBase64);
            clientEphemeralBigInteger = new BigInteger(clientEphemeralBytes);
        } catch (Exception ex) {
            throw new UnauthorizedException("Could not decode client ephemeral.", ex);
        }

        try {
            srp.calculateSecret(clientEphemeralBigInteger);
        } catch (Exception ex) {
            throw new UnauthorizedException("SRP secret could not be calculated.", ex);
        }

        BigInteger clientProofBigInteger;
        try {
            String clientProofBase64 = request.getClientProofBase64();
            byte[] clientProofBytes = Base64.getDecoder().decode(clientProofBase64);
            clientProofBigInteger = new BigInteger(clientProofBytes);
        } catch (Exception ex) {
            throw new UnauthorizedException("Could not decode client proof.", ex);
        }

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
            throw new UnauthorizedException("Session key could not be calculated.", ex);
        }

        byte[] authenticationSessionKeyBytes = authenticationSessionKeyBigInteger.toByteArray();
        AuthenticationSession authenticationSession =
            AuthenticationSessionHelper.createAuthenticationSessionWithKey(authenticationSessionKeyBytes);

        Set<AuthenticationSession> authenticationSessions =
            Optional.ofNullable(currentAuthentication.getAuthenticationSessions()).orElse(new HashSet<>());
        authenticationSessions.add(authenticationSession);
        currentAuthentication.setAuthenticationSessions(authenticationSessions);

        userIdentityRepository.save(userIdentity);

        String serverProofBase64 = Base64.getEncoder().encodeToString(serverProofBigInteger.toByteArray());
        String authenticationSessionId = authenticationSession.getId();

        return new PasswordAuthenticationCompleteV1Response(serverProofBase64, authenticationSessionId);
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

        return userIdentityHelper.dummyUserIdentity(null);
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

    public byte[] getAuthenticationSessionKeyByAuthenticationSessionId(String authenticationSessionId) {
        if (authenticationSessionId == null) {
            throw new IllegalArgumentException("deviceId must not be null");
        }

        if (authenticationSessionId.equals("")) {
            throw new IllegalArgumentException("deviceId must not be empty");
        }

        return new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    }

}
