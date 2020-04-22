package org.diplomatiq.diplomatiqbackend.services;

import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.*;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.AuthenticationSessionHelper;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserDeviceHelper;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.AbstractPasswordStretchingAlgorithmImpl;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingEngine;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.InternalServerError;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationDetails;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationToken;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.PasswordAuthenticationCompleteV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.PasswordAuthenticationInitV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.LoginV1Response;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationCompleteV1Response;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationInitV1Response;
import org.diplomatiq.diplomatiqbackend.repositories.AuthenticationSessionRepository;
import org.diplomatiq.diplomatiqbackend.repositories.UserDeviceRepository;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.diplomatiq.diplomatiqbackend.utils.crypto.aead.DiplomatiqAEAD;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.diplomatiq.diplomatiqbackend.utils.crypto.srp.RequestBoundaryCrossingSRP6Server;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
    private UserDeviceRepository userDeviceRepository;

    @Autowired
    private AuthenticationSessionRepository authenticationSessionRepository;

    @Autowired
    private PasswordStretchingEngine passwordStretchingEngine;

    @Autowired
    private UserIdentityHelper userIdentityHelper;

    @Autowired
    private UserDeviceHelper userDeviceHelper;

    public byte[] getDeviceContainerKeyV1(String deviceId) {
        UserDevice userDevice = userDeviceRepository.findById(deviceId).orElse(userDeviceHelper.createUserDevice());
        return userDevice.getDeviceContainerKey();
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

    public PasswordAuthenticationCompleteV1Response passwordAuthenticationCompleteV1(PasswordAuthenticationCompleteV1Request request) {
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
            throw new UnauthorizedException("Previous server ephemeral value not found.");
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
            throw new UnauthorizedException("Client proof could not be verified.");
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

    public LoginV1Response loginV1() throws NoSuchPaddingException, InvalidKeyException,
        NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
        IOException {
        String authenticationSessionId = getCurrentAuthenticationDetails().getAuthenticationId();
        AuthenticationSession authenticationSession = authenticationSessionRepository.findById(authenticationSessionId)
            .orElseThrow(() -> new UnauthorizedException("Did not find authentication session with the supplied ID."));

        UserIdentity userIdentity = authenticationSession.getUserAuthentication().getUserIdentity();
        Set<UserDevice> userDevices = userIdentity.getDevices();

        UserDevice userDevice = userDeviceHelper.createUserDevice();
        userDevices.add(userDevice);

        userIdentityRepository.save(userIdentity);

        String deviceId = userDevice.getId();

        byte[] authenticationSessionKey = authenticationSession.getAuthenticationSessionKey();

        byte[] deviceKey = userDevice.getDeviceKey();
        DiplomatiqAEAD deviceKeyAead = new DiplomatiqAEAD(deviceKey);
        byte[] deviceKeyAeadBytes = deviceKeyAead.toBytes(authenticationSessionKey);
        String deviceKeyAeadBase64 = Base64.getEncoder().encodeToString(deviceKeyAeadBytes);

        byte[] sessionToken = userDevice.getSessionToken();
        DiplomatiqAEAD sessionTokenAead = new DiplomatiqAEAD(sessionToken);
        byte[] sessionTokenAeadBytes = sessionTokenAead.toBytes(authenticationSessionKey);
        String sessionTokenAeadBase64 = Base64.getEncoder().encodeToString(sessionTokenAeadBytes);

        return new LoginV1Response(deviceId, deviceKeyAeadBase64, sessionTokenAeadBase64);
    }

    public UserIdentity getCurrentUserIdentity() {
        return getCurrentAuthenticatedAuthenticationToken().getPrincipal();
    }

    public AuthenticationDetails getCurrentAuthenticationDetails() {
        return getCurrentAuthenticatedAuthenticationToken().getCredentials();
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

    private AuthenticationToken getCurrentAuthenticatedAuthenticationToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new IllegalStateException("There is no authentication in the SecurityContext.");
        }

        if (!(authentication instanceof AuthenticationToken)) {
            throw new InternalServerError("SecurityContext contains something else instead of an AuthenticationToken.");
        }

        return (AuthenticationToken) authentication;
    }
}
