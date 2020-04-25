package org.diplomatiq.diplomatiqbackend.services;

import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.Arrays;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.*;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.*;
import org.diplomatiq.diplomatiqbackend.domain.entities.utils.ExpirationUtils;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingEngine;
import org.diplomatiq.diplomatiqbackend.engines.mail.EmailSendingEngine;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.BadRequestException;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.ExpiredException;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.InternalServerError;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationDetails;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationToken;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.*;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.*;
import org.diplomatiq.diplomatiqbackend.repositories.*;
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
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Transactional
public class AuthenticationService {
    @Autowired
    private EmailSendingEngine emailSendingEngine;

    @Autowired
    private PasswordStretchingEngine passwordStretchingEngine;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private UserDeviceRepository userDeviceRepository;

    @Autowired
    private AuthenticationSessionRepository authenticationSessionRepository;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private UserAuthenticationResetRequestRepository userAuthenticationResetRequestRepository;

    @Autowired
    private UserIdentityHelper userIdentityHelper;

    @Autowired
    private UserDeviceHelper userDeviceHelper;

    @Autowired
    private UserAuthenticationResetRequestHelper userAuthenticationResetRequestHelper;

    @Autowired
    private UserAuthenticationHelper userAuthenticationHelper;

    public byte[] getDeviceContainerKeyV1(String deviceId) {
        UserDevice userDevice = userDeviceRepository.findById(deviceId).orElse(userDeviceHelper.createUserDevice());
        return userDevice.getDeviceContainerKey();
    }

    public GetSessionV1Response getSessionV1(GetSessionV1Request request) throws NoSuchPaddingException,
        InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException,
        InvalidAlgorithmParameterException {
        String currentDeviceId = getCurrentAuthenticationDetails().getAuthenticationId();

        UserDevice userDevice;
        try {
            userDevice = userDeviceRepository.findById(currentDeviceId).orElseThrow();
        } catch (Exception ex) {
            throw new UnauthorizedException("Could not retrieve device key.", ex);
        }

        Session oldSession = userDevice.getSession();
        if (oldSession != null) {
            if (ExpirationUtils.isExpiredIn(oldSession, Duration.ofMinutes(1))) {
                byte[] sessionIdBytes = oldSession.getId().getBytes(StandardCharsets.UTF_8);
                DiplomatiqAEAD sessionIdAead = new DiplomatiqAEAD(sessionIdBytes);
                byte[] sessionIdAeadBytes = sessionIdAead.toBytes(userDevice.getDeviceKey());
                String sessionIdAeadBase64 = Base64.getEncoder().encodeToString(sessionIdAeadBytes);
                return new GetSessionV1Response(sessionIdAeadBase64);
            }
        }

        byte[] sessionTokenAeadBytes;
        try {
            sessionTokenAeadBytes = Base64.getDecoder().decode(request.getSessionTokenAeadBase64());
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Session token could not be decoded.", ex);
        }

        DiplomatiqAEAD sessionTokenAead;
        try {
            sessionTokenAead = DiplomatiqAEAD.fromBytes(sessionTokenAeadBytes, userDevice.getDeviceKey());
        } catch (Exception ex) {
            throw new UnauthorizedException("Session token could not be decrypted.", ex);
        }

        byte[] sessionToken = sessionTokenAead.getPlaintext();
        if (!Arrays.constantTimeAreEqual(sessionToken, userDevice.getSessionToken())) {
            throw new UnauthorizedException("Session token and device are unrelated.");
        }

        Session newSession = SessionHelper.createSession();
        byte[] sessionIdBytes = newSession.getId().getBytes(StandardCharsets.UTF_8);
        DiplomatiqAEAD sessionIdAead = new DiplomatiqAEAD(sessionIdBytes);
        byte[] sessionIdAeadBytes = sessionIdAead.toBytes(userDevice.getDeviceKey());
        String sessionIdAeadBase64 = Base64.getEncoder().encodeToString(sessionIdAeadBytes);

        userDevice.setSession(newSession);
        userDeviceRepository.save(userDevice);

        return new GetSessionV1Response(sessionIdAeadBase64);
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

    public void logoutV1() {
        String sessionId = getCurrentAuthenticationDetails().getAuthenticationId();

        Session session = sessionRepository.findById(sessionId).orElseThrow();
        UserDevice userDevice = session.getUserDevice();

        sessionRepository.delete(session);
        userDeviceRepository.delete(userDevice);

        SecurityContextHolder.clearContext();
    }

    public PasswordAuthenticationInitV1Response passwordAuthenticationInitV1(PasswordAuthenticationInitV1Request request) throws NoSuchAlgorithmException {
        String emailAddress = request.getEmailAddress().toLowerCase();
        Optional<UserIdentity> userIdentityOptional = userIdentityRepository.findByEmailAddress(emailAddress);
        boolean existingUser = userIdentityOptional.isPresent();

        UserIdentity userIdentity;
        if (existingUser) {
            userIdentity = userIdentityOptional.get();
        } else {
            userIdentity = userIdentityHelper.createUserIdentity(emailAddress, "", "");
            byte[] salt = RandomUtils.bytes(32);
            byte[] verifier = RandomUtils.bytes(1024);
            PasswordStretchingAlgorithm passwordStretchingAlgorithm = passwordStretchingEngine.getLatestAlgorithm();
            UserAuthentication userAuthentication = userAuthenticationHelper.createUserAuthentication(userIdentity,
                salt, verifier, passwordStretchingAlgorithm);
            userIdentity.setAuthentications(Set.of(userAuthentication));
        }

        UserAuthentication currentAuthentication = userIdentityHelper.getCurrentAuthentication(userIdentity);

        byte[] srpVerifierBytes = currentAuthentication.getSrpVerifier();
        BigInteger srpVerifierBigInteger = new BigInteger(srpVerifierBytes);

        RequestBoundaryCrossingSRP6Server srp = new RequestBoundaryCrossingSRP6Server();
        srp.init(SRP6StandardGroups.rfc5054_8192, srpVerifierBigInteger, new SHA256Digest(),
            RandomUtils.getStrongSecureRandom());

        BigInteger serverEphemeralBigInteger = srp.generateServerCredentials();
        byte[] serverEphemeralBytes = serverEphemeralBigInteger.toByteArray();
        String serverEphemeralBase64 = Base64.getEncoder().encodeToString(serverEphemeralBytes);

        byte[] srpSaltBytes = currentAuthentication.getSrpSalt();
        String srpSaltBase64 = Base64.getEncoder().encodeToString(srpSaltBytes);

        Set<UserTemporarySRPData> userTemporarySRPDatas =
            currentAuthentication.getUserTemporarySrpDatas();

        UserTemporarySRPData userTemporarySRPData = UserTemporarySRPDataHelper.create(serverEphemeralBytes);
        userTemporarySRPDatas.add(userTemporarySRPData);

        if (existingUser) {
            userIdentityRepository.save(userIdentity);
        }

        return new PasswordAuthenticationInitV1Response(serverEphemeralBase64, srpSaltBase64,
            currentAuthentication.getPasswordStretchingAlgorithm());
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
            .orElseThrow(() -> new UnauthorizedException("UserIdentity not found."));
        UserAuthentication currentAuthentication = userIdentityHelper.getCurrentAuthentication(userIdentity);

        byte[] srpVerifierBytes = currentAuthentication.getSrpVerifier();
        BigInteger srpVerifierBigInteger = new BigInteger(srpVerifierBytes);

        PasswordStretchingAlgorithm passwordStretchingAlgorithm =
            currentAuthentication.getPasswordStretchingAlgorithm();

        RequestBoundaryCrossingSRP6Server srp = new RequestBoundaryCrossingSRP6Server();
        srp.init(SRP6StandardGroups.rfc5054_8192, srpVerifierBigInteger, new SHA256Digest(),
            RandomUtils.getStrongSecureRandom());

        Set<UserTemporarySRPData> userTemporarySrpDatas =
            currentAuthentication.getUserTemporarySrpDatas();
        userTemporarySrpDatas.removeIf(ExpirationUtils::isExpiredNow);
        boolean foundNonExpired = userTemporarySrpDatas.removeIf(d ->
            Arrays.constantTimeAreEqual(d.getServerEphemeral(), serverEphemeralBytes));

        if (!foundNonExpired) {
            throw new UnauthorizedException("Previous, still valid server ephemeral value not found.");
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

    public ElevateRegularSessionInitV1Response elevateRegularSessionInitV1() {
        UserIdentity userIdentity = getCurrentUserIdentity();
        UserAuthentication currentAuthentication = userIdentityHelper.getCurrentAuthentication(userIdentity);

        byte[] srpVerifierBytes = currentAuthentication.getSrpVerifier();
        BigInteger srpVerifierBigInteger = new BigInteger(srpVerifierBytes);

        RequestBoundaryCrossingSRP6Server srp = new RequestBoundaryCrossingSRP6Server();
        srp.init(SRP6StandardGroups.rfc5054_8192, srpVerifierBigInteger, new SHA256Digest(),
            RandomUtils.getStrongSecureRandom());

        BigInteger serverEphemeralBigInteger = srp.generateServerCredentials();
        byte[] serverEphemeralBytes = serverEphemeralBigInteger.toByteArray();
        String serverEphemeralBase64 = Base64.getEncoder().encodeToString(serverEphemeralBytes);

        byte[] srpSaltBytes = currentAuthentication.getSrpSalt();
        String srpSaltBase64 = Base64.getEncoder().encodeToString(srpSaltBytes);

        Set<UserTemporarySRPData> userTemporarySRPDatas =
            currentAuthentication.getUserTemporarySrpDatas();

        UserTemporarySRPData userTemporarySRPData = UserTemporarySRPDataHelper.create(serverEphemeralBytes);
        userTemporarySRPDatas.add(userTemporarySRPData);

        userIdentityRepository.save(userIdentity);

        return new ElevateRegularSessionInitV1Response(serverEphemeralBase64, srpSaltBase64);
    }

    public void elevateRegularSessionCompleteV1(ElevateRegularSessionCompleteV1Request request) {
        UserIdentity userIdentity = getCurrentUserIdentity();
        UserAuthentication currentAuthentication = userIdentityHelper.getCurrentAuthentication(userIdentity);

        byte[] serverEphemeralBytes;
        try {
            String serverEphemeralBase64 = request.getServerEphemeralBase64();
            serverEphemeralBytes = Base64.getDecoder().decode(serverEphemeralBase64);
        } catch (Exception ex) {
            throw new UnauthorizedException("Could not decode server ephemeral.", ex);
        }

        byte[] srpVerifierBytes = currentAuthentication.getSrpVerifier();
        BigInteger srpVerifierBigInteger = new BigInteger(srpVerifierBytes);

        RequestBoundaryCrossingSRP6Server srp = new RequestBoundaryCrossingSRP6Server();
        srp.init(SRP6StandardGroups.rfc5054_8192, srpVerifierBigInteger, new SHA256Digest(),
            RandomUtils.getStrongSecureRandom());

        Set<UserTemporarySRPData> userTemporarySrpData =
            currentAuthentication.getUserTemporarySrpDatas();
        Set<ByteBuffer> savedServerEphemerals = userTemporarySrpData.stream()
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

        String sessionId = getCurrentAuthenticationDetails().getAuthenticationId();
        Session session = sessionRepository.findById(sessionId).orElseThrow();
        Session elevatedSession = SessionHelper.elevateSessionToPasswordElevated(session);
        sessionRepository.save(elevatedSession);
    }

    public void validateEmailAddressV1(String emailValidationKey) {
        Optional<UserIdentity> userIdentityOptional =
            userIdentityRepository.findByEmailValidationKey(emailValidationKey);
        if (userIdentityOptional.isPresent()) {
            UserIdentity userIdentity = userIdentityOptional.get();
            userIdentity.setEmailValidated(true);
            userIdentityRepository.save(userIdentity);
        }
    }

    public void requestPasswordResetV1(String emailAddress) throws IOException {
        Optional<UserIdentity> userIdentityOptional =
            userIdentityRepository.findByEmailAddress(emailAddress.toLowerCase());
        if (userIdentityOptional.isPresent()) {
            UserIdentity userIdentity = userIdentityOptional.get();
            UserAuthentication userAuthentication = userIdentityHelper.getCurrentAuthentication(userIdentity);
            UserAuthenticationResetRequest userAuthenticationResetRequest =
                userAuthenticationResetRequestHelper.create();
            Set<UserAuthenticationResetRequest> userAuthenticationResetRequests =
                userAuthentication.getUserAuthenticationResetRequests();
            userAuthenticationResetRequests.add(userAuthenticationResetRequest);
            userIdentityRepository.save(userIdentity);
            emailSendingEngine.sendPasswordResetEmail(userAuthenticationResetRequest);
        }
    }

    public void resetPasswordV1(ResetPasswordV1Request request) {
        Optional<UserAuthenticationResetRequest> userAuthenticationResetRequestOptional =
            userAuthenticationResetRequestRepository.findByRequestKey(request.getPasswordResetKey());
        if (userAuthenticationResetRequestOptional.isPresent()) {
            byte[] srpSalt;
            try {
                srpSalt = Base64.getDecoder().decode(request.getSrpSaltBase64());
            } catch (Exception ex) {
                throw new BadRequestException("SRP salt could not be decoded.", ex);
            }

            byte[] srpVerifier;
            try {
                srpVerifier = Base64.getDecoder().decode(request.getSrpSaltBase64());
            } catch (Exception ex) {
                throw new BadRequestException("SRP verifier could not be decoded.", ex);
            }

            UserAuthenticationResetRequest userAuthenticationResetRequest =
                userAuthenticationResetRequestOptional.get();
            if (ExpirationUtils.isExpiredNow(userAuthenticationResetRequest)) {
                throw new UnauthorizedException("Password reset request expired.");
            }

            UserIdentity userIdentity = userAuthenticationResetRequest.getUserAuthentication().getUserIdentity();
            UserAuthentication userAuthentication = userAuthenticationHelper.createUserAuthentication(userIdentity,
                srpSalt, srpVerifier, request.getPasswordStretchingAlgorithm());
            Set<UserAuthentication> userAuthentications = userIdentity.getAuthentications();
            userAuthentications.add(userAuthentication);
            userIdentity.setAuthentications(userAuthentications);

            userIdentityRepository.save(userIdentity);
            userAuthenticationResetRequestRepository.delete(userAuthenticationResetRequest);
        }
    }

    public UserIdentity getCurrentUserIdentity() {
        return getCurrentAuthenticatedAuthenticationToken().getPrincipal();
    }

    public AuthenticationDetails getCurrentAuthenticationDetails() {
        return getCurrentAuthenticatedAuthenticationToken().getCredentials();
    }

    public byte[] getDeviceKeyByDeviceId(String deviceId) {
        UserDevice userDevice = userDeviceRepository.findById(deviceId).orElseThrow();
        return userDevice.getDeviceKey();
    }

    public byte[] getAuthenticationSessionKeyByAuthenticationSessionId(String authenticationSessionId) {
        AuthenticationSession authenticationSession =
            authenticationSessionRepository.findById(authenticationSessionId).orElseThrow();
        return authenticationSession.getAuthenticationSessionKey();
    }

    @Transactional(noRollbackFor = { ExpiredException.class })
    public UserIdentity verifyAuthenticationSessionCredentials(String authenticationSessionId) {
        AuthenticationSession authenticationSession =
            authenticationSessionRepository.findById(authenticationSessionId).orElseThrow();

        if (ExpirationUtils.isExpiredNow(authenticationSession)) {
            authenticationSessionRepository.delete(authenticationSession);
            throw new ExpiredException("Authentication session expired.");
        }

        return authenticationSession.getUserAuthentication().getUserIdentity();
    }

    public UserIdentity verifyDeviceCredentials(String deviceId) {
        UserDevice userDevice = userDeviceRepository.findById(deviceId).orElseThrow();
        return userDevice.getUserIdentity();
    }

    @Transactional(noRollbackFor = { ExpiredException.class })
    public UserIdentity verifySessionCredentials(String deviceId, String sessionId) {
        UserDevice userDevice = userDeviceRepository.findById(deviceId).orElseThrow();
        Session session = sessionRepository.findById(sessionId).orElseThrow();

        if (!userDevice.getSession().equals(session)) {
            throw new UnauthorizedException("Device and session are unrelated.");
        }

        if (ExpirationUtils.isExpiredNow(session)) {
            sessionRepository.delete(session);
            throw new ExpiredException("Session expired.");
        }

        return userDevice.getUserIdentity();
    }

    private AuthenticationToken getCurrentAuthenticatedAuthenticationToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new IllegalStateException("There is no authentication in the SecurityContext.");
        }

        if (!(authentication instanceof AuthenticationToken)) {
            throw new InternalServerError("SecurityContext contains something else instead of an AuthenticationToken.");
        }

        return (AuthenticationToken)authentication;
    }
}
