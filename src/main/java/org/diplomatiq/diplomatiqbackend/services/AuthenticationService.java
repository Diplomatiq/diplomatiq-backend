package org.diplomatiq.diplomatiqbackend.services;

import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.util.Arrays;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.*;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.*;
import org.diplomatiq.diplomatiqbackend.domain.entities.utils.ExpirationUtils;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingEngine;
import org.diplomatiq.diplomatiqbackend.engines.mail.EmailSendingEngine;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.BadRequestException;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.InternalServerError;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationDetails;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationToken;
import org.diplomatiq.diplomatiqbackend.methods.attributes.SessionAssuranceLevel;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.*;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.*;
import org.diplomatiq.diplomatiqbackend.repositories.*;
import org.diplomatiq.diplomatiqbackend.utils.crypto.aead.DiplomatiqAEAD;
import org.diplomatiq.diplomatiqbackend.utils.crypto.convert.BigIntegerToByteArray;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.diplomatiq.diplomatiqbackend.utils.crypto.srp.RequestBoundaryCrossingSRP6Server;
import org.diplomatiq.diplomatiqbackend.utils.crypto.srp.SRP6Factory;
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
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

@Service
@Transactional
public class AuthenticationService {
    @Autowired
    private EmailSendingEngine emailSendingEngine;

    @Autowired
    private SRP6Factory srp6Factory;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private UserTemporarySRPDataRepository userTemporarySRPDataRepository;

    @Autowired
    private UserAuthenticationRepository userAuthenticationRepository;

    @Autowired
    private UserDeviceRepository userDeviceRepository;

    @Autowired
    private AuthenticationSessionRepository authenticationSessionRepository;

    @Autowired
    private AuthenticationSessionMultiFactorElevationRequestRepository authenticationSessionMultiFactorElevationRequestRepository;

    @Autowired
    private SessionMultiFactorElevationRequestRepository sessionMultiFactorElevationRequestRepository;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private UserAuthenticationResetRequestRepository userAuthenticationResetRequestRepository;

    public GetDeviceContainerKeyV1Response getDeviceContainerKeyV1(String deviceId) {
        UserDevice userDevice = userDeviceRepository.findById(deviceId).orElse(UserDeviceHelper.create());
        byte[] deviceContainerKeyBytes = userDevice.getDeviceContainerKey();
        String deviceContainerKeyBase64 = Base64.getEncoder().encodeToString(deviceContainerKeyBytes);
        return new GetDeviceContainerKeyV1Response(deviceContainerKeyBase64);
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
            if (!ExpirationUtils.isExpiredIn(oldSession, Duration.ofMinutes(1))) {
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

        Session newSession = SessionHelper.create();
        newSession.setUserDevice(userDevice);
        Session persistedNewSession = sessionRepository.save(newSession);

        String sessionId = persistedNewSession.getId();
        byte[] sessionIdBytes = sessionId.getBytes(StandardCharsets.UTF_8);
        DiplomatiqAEAD sessionIdAead = new DiplomatiqAEAD(sessionIdBytes);
        byte[] sessionIdAeadBytes = sessionIdAead.toBytes(userDevice.getDeviceKey());
        String sessionIdAeadBase64 = Base64.getEncoder().encodeToString(sessionIdAeadBytes);

        return new GetSessionV1Response(sessionIdAeadBase64);
    }

    public LoginV1Response loginV1() throws NoSuchPaddingException, InvalidKeyException,
        NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
        IOException {
        String authenticationSessionId = getCurrentAuthenticationDetails().getAuthenticationId();
        AuthenticationSession authenticationSession =
            authenticationSessionRepository.findById(authenticationSessionId, 2).orElseThrow();

        UserDevice userDevice = UserDeviceHelper.create();
        userDevice.setUserIdentity(authenticationSession.getUserAuthentication().getUserIdentity());
        UserDevice persistedUserDevice = userDeviceRepository.save(userDevice);

        byte[] authenticationSessionKey = authenticationSession.getAuthenticationSessionKey();

        byte[] deviceKey = persistedUserDevice.getDeviceKey();
        DiplomatiqAEAD deviceKeyAead = new DiplomatiqAEAD(deviceKey);
        byte[] deviceKeyAeadBytes = deviceKeyAead.toBytes(authenticationSessionKey);
        String deviceKeyAeadBase64 = Base64.getEncoder().encodeToString(deviceKeyAeadBytes);

        String deviceId = persistedUserDevice.getId();
        byte[] deviceIdBytes = deviceId.getBytes(StandardCharsets.UTF_8);
        DiplomatiqAEAD deviceIdAead = new DiplomatiqAEAD(deviceIdBytes);
        byte[] deviceIdAeadBytes = deviceIdAead.toBytes(deviceKey);
        String deviceIdAeadBase64 = Base64.getEncoder().encodeToString(deviceIdAeadBytes);

        byte[] sessionToken = persistedUserDevice.getSessionToken();
        DiplomatiqAEAD sessionTokenAead = new DiplomatiqAEAD(sessionToken);
        byte[] sessionTokenAeadBytes = sessionTokenAead.toBytes(deviceKey);
        String sessionTokenAeadBase64 = Base64.getEncoder().encodeToString(sessionTokenAeadBytes);

        return new LoginV1Response(deviceIdAeadBase64, deviceKeyAeadBase64, sessionTokenAeadBase64);
    }

    public void logoutV1() {
        String deviceId = getCurrentAuthenticationDetails().getAuthenticationId();

        UserDevice userDevice = userDeviceRepository.findById(deviceId).orElseThrow();
        Session session = userDevice.getSession();

        sessionRepository.delete(session);
        userDeviceRepository.delete(userDevice);
    }

    public PasswordAuthenticationInitV1Response passwordAuthenticationInitV1(PasswordAuthenticationInitV1Request request) throws NoSuchAlgorithmException {
        String emailAddress = request.getEmailAddress().toLowerCase();
        Optional<UserIdentity> userIdentityOptional = userIdentityRepository.findByEmailAddress(emailAddress, 2);
        boolean existingUser = userIdentityOptional.isPresent();

        UserIdentity userIdentity;
        if (existingUser) {
            userIdentity = userIdentityOptional.get();
        } else {
            userIdentity = UserIdentityHelper.create(emailAddress, "", "");

            byte[] saltBytes = RandomUtils.bytes(32);
            byte[] identityBytes = userIdentity.getEmailAddress().getBytes(StandardCharsets.UTF_8);
            byte[] passwordBytes = RandomUtils.bytes(20);

            SRP6VerifierGenerator srp6VerifierGenerator = srp6Factory.getSrp6VerifierGenerator();
            BigInteger srpVerifierBigInteger = srp6VerifierGenerator.generateVerifier(saltBytes, identityBytes,
                passwordBytes);

            String srpSaltHex = new BigInteger(1, saltBytes).toString(16);
            String srpVerifierHex = srpVerifierBigInteger.toString(16);
            PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingEngine.getLatestAlgorithm();
            UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity,
                srpSaltHex, srpVerifierHex, passwordStretchingAlgorithm);
            userIdentity.setAuthentications(Set.of(userAuthentication));
        }

        UserAuthentication currentAuthentication = UserIdentityHelper.getCurrentAuthentication(userIdentity);
        BigInteger srpVerifierBigInteger = new BigInteger(currentAuthentication.getSrpVerifierHex(), 16);

        RequestBoundaryCrossingSRP6Server srp = srp6Factory.getSrp6Server(srpVerifierBigInteger);

        BigInteger serverEphemeralBigInteger = srp.generateServerCredentials();
        String serverEphemeralHex = serverEphemeralBigInteger.toString(16);

        BigInteger serverSecretBigInteger = srp.getb();
        String serverSecretHex = serverSecretBigInteger.toString(16);

        UserTemporarySRPData userTemporarySRPData = UserTemporarySRPDataHelper.create(serverEphemeralHex,
            serverSecretHex);
        currentAuthentication.getUserTemporarySrpDatas().add(userTemporarySRPData);

        if (existingUser) {
            userIdentityRepository.save(userIdentity);
        }

        String srpSaltHex = currentAuthentication.getSrpSaltHex();
        return new PasswordAuthenticationInitV1Response(serverEphemeralHex, srpSaltHex,
            currentAuthentication.getPasswordStretchingAlgorithm());
    }

    public PasswordAuthenticationCompleteV1Response passwordAuthenticationCompleteV1(PasswordAuthenticationCompleteV1Request request) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        String emailAddress = request.getEmailAddress().toLowerCase();

        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress, 2)
            .orElseThrow(() -> new UnauthorizedException("UserIdentity not found."));
        UserAuthentication currentAuthentication = UserIdentityHelper.getCurrentAuthentication(userIdentity);

        BigInteger srpVerifierBigInteger = new BigInteger(currentAuthentication.getSrpVerifierHex(), 16);

        RequestBoundaryCrossingSRP6Server srp = srp6Factory.getSrp6Server(srpVerifierBigInteger);

        Set<UserTemporarySRPData> userTemporarySrpDatas = currentAuthentication.getUserTemporarySrpDatas();
        userTemporarySrpDatas.removeIf(ExpirationUtils::isExpiredNow);

        UserTemporarySRPData foundUserTemporarySrpData = null;
        for (UserTemporarySRPData userTemporarySRPData : userTemporarySrpDatas) {
            if (userTemporarySRPData.getServerEphemeralHex().equals(request.getServerEphemeralHex())) {
                foundUserTemporarySrpData = userTemporarySRPData;
                userTemporarySrpDatas.remove(userTemporarySRPData);
                break;
            }
        }

        if (foundUserTemporarySrpData == null) {
            throw new UnauthorizedException("Previous, still valid server ephemeral value not found.");
        }

        BigInteger serverSecretBigInteger = new BigInteger(foundUserTemporarySrpData.getServerSecretHex(), 16);
        srp.setb(serverSecretBigInteger);

        BigInteger serverEphemeralBigInteger = new BigInteger(foundUserTemporarySrpData.getServerEphemeralHex(), 16);
        srp.setB(serverEphemeralBigInteger);

        userTemporarySRPDataRepository.delete(foundUserTemporarySrpData);

        BigInteger clientEphemeralBigInteger = new BigInteger(request.getClientEphemeralHex(), 16);
        try {
            srp.calculateSecret(clientEphemeralBigInteger);
        } catch (Exception ex) {
            throw new UnauthorizedException("SRP secret could not be calculated.", ex);
        }

        BigInteger clientProofBigInteger = new BigInteger(request.getClientProofHex(), 16);
        boolean clientProofVerified;
        try {
            clientProofVerified = srp.verifyClientEvidenceMessage(clientProofBigInteger);
        } catch (Exception ex) {
            throw new UnauthorizedException("Crypto error during client proof verification.", ex);
        }

        if (!clientProofVerified) {
            throw new UnauthorizedException("Client proof could not be verified.");
        }

        try {
            srp.calculateServerEvidenceMessage();
        } catch (Exception ex) {
            throw new UnauthorizedException("Crypto error during server proof calculation.", ex);
        }

        BigInteger authenticationSessionKeyBigInteger;
        try {
            authenticationSessionKeyBigInteger = srp.calculateSessionKey();
        } catch (Exception ex) {
            throw new UnauthorizedException("Session key could not be calculated.", ex);
        }

        byte[] authenticationSessionKeyBytes = BigIntegerToByteArray.convert(authenticationSessionKeyBigInteger);
        AuthenticationSession authenticationSession =
            AuthenticationSessionHelper.create(authenticationSessionKeyBytes);
        authenticationSession.setUserAuthentication(currentAuthentication);

        AuthenticationSession persistedAuthenticationSession =
            authenticationSessionRepository.save(authenticationSession);

        String authenticationSessionId = persistedAuthenticationSession.getId();
        byte[] authenticationSessionIdBytes = authenticationSessionId.getBytes(StandardCharsets.UTF_8);
        DiplomatiqAEAD authenticationSessionIdAead = new DiplomatiqAEAD(authenticationSessionIdBytes);
        byte[] authenticationSessionIdAeadBytes = authenticationSessionIdAead.toBytes(authenticationSessionKeyBytes);
        String authenticationSessionIdAeadBase64 = Base64.getEncoder().encodeToString(authenticationSessionIdAeadBytes);

        return new PasswordAuthenticationCompleteV1Response(authenticationSessionIdAeadBase64);
    }

    public void elevateAuthenticationSessionInitV1() throws IOException {
        String authenticationSessionid = getCurrentAuthenticationDetails().getAuthenticationId();
        AuthenticationSession authenticationSession = authenticationSessionRepository
            .findById(authenticationSessionid)
            .orElseThrow();

        AuthenticationSessionMultiFactorElevationRequest elevationRequest =
            AuthenticationSessionMultiFactorElevationRequestHelper.create();
        elevationRequest.setAuthenticationSession(authenticationSession);
        authenticationSessionMultiFactorElevationRequestRepository.save(elevationRequest);

        emailSendingEngine.sendMultiFactorAuthenticationEmail(elevationRequest);
    }

    public void elevateAuthenticationSessionCompleteV1(ElevateAuthenticationSessionCompleteV1Request request) {
        String authenticationCode = request.getRequestCode();

        AuthenticationSession authenticationSession = authenticationSessionRepository
            .findById(getCurrentAuthenticationDetails().getAuthenticationId())
            .orElseThrow();
        Set<AuthenticationSessionMultiFactorElevationRequest> authenticationSessionMultiFactorElevationRequests =
            authenticationSession.getAuthenticationSessionMultiFactorElevationRequests();
        authenticationSessionMultiFactorElevationRequests.removeIf(ExpirationUtils::isExpiredNow);
        boolean authenticationCodeFound = authenticationSessionMultiFactorElevationRequests
            .removeIf(r -> r.getRequestCode().equals(authenticationCode));
        if (!authenticationCodeFound) {
            throw new UnauthorizedException("Authentication code not found.");
        }

        AuthenticationSessionHelper.elevateAuthenticationSessionToMultiFactorElevated(authenticationSession);
        authenticationSessionRepository.save(authenticationSession);
    }

    public ElevateRegularSessionInitV1Response elevateRegularSessionInitV1() {
        UserIdentity userIdentity = userIdentityRepository.findById(getCurrentUserIdentity().getId(), 2).orElseThrow();
        UserAuthentication currentAuthentication = UserIdentityHelper.getCurrentAuthentication(userIdentity);

        BigInteger srpVerifierBigInteger = new BigInteger(currentAuthentication.getSrpVerifierHex(), 16);

        RequestBoundaryCrossingSRP6Server srp = srp6Factory.getSrp6Server(srpVerifierBigInteger);

        BigInteger serverEphemeralBigInteger = srp.generateServerCredentials();
        String serverEphemeralHex = serverEphemeralBigInteger.toString(16);

        BigInteger serverSecretBigInteger = srp.getb();
        String serverSecretHex = serverSecretBigInteger.toString(16);

        UserTemporarySRPData userTemporarySRPData = UserTemporarySRPDataHelper.create(serverEphemeralHex,
            serverSecretHex);
        currentAuthentication.getUserTemporarySrpDatas().add(userTemporarySRPData);

        userIdentityRepository.save(userIdentity);

        String srpSaltHex = currentAuthentication.getSrpSaltHex();
        PasswordStretchingAlgorithm passwordStretchingAlgorithm =
            currentAuthentication.getPasswordStretchingAlgorithm();
        return new ElevateRegularSessionInitV1Response(serverEphemeralHex, srpSaltHex, passwordStretchingAlgorithm);
    }

    public void elevateRegularSessionCompleteV1(ElevateRegularSessionCompleteV1Request request) {
        UserIdentity userIdentity = userIdentityRepository.findById(getCurrentUserIdentity().getId(), 2).orElseThrow();
        UserAuthentication currentAuthentication = UserIdentityHelper.getCurrentAuthentication(userIdentity);

        BigInteger srpVerifierBigInteger = new BigInteger(currentAuthentication.getSrpVerifierHex(), 16);

        RequestBoundaryCrossingSRP6Server srp = srp6Factory.getSrp6Server(srpVerifierBigInteger);

        Set<UserTemporarySRPData> userTemporarySrpDatas = currentAuthentication.getUserTemporarySrpDatas();
        userTemporarySrpDatas.removeIf(ExpirationUtils::isExpiredNow);

        UserTemporarySRPData foundUserTemporarySrpData = null;
        for (UserTemporarySRPData userTemporarySRPData : userTemporarySrpDatas) {
            if (userTemporarySRPData.getServerEphemeralHex().equals(request.getServerEphemeralHex())) {
                foundUserTemporarySrpData = userTemporarySRPData;
                userTemporarySrpDatas.remove(userTemporarySRPData);
                break;
            }
        }

        if (foundUserTemporarySrpData == null) {
            throw new UnauthorizedException("Previous, still valid server ephemeral value not found.");
        }

        BigInteger serverSecretBigInteger = new BigInteger(foundUserTemporarySrpData.getServerSecretHex(), 16);
        srp.setb(serverSecretBigInteger);

        BigInteger serverEphemeralBigInteger = new BigInteger(foundUserTemporarySrpData.getServerEphemeralHex(), 16);
        srp.setB(serverEphemeralBigInteger);

        userTemporarySRPDataRepository.delete(foundUserTemporarySrpData);

        BigInteger clientEphemeralBigInteger = new BigInteger(request.getClientEphemeralHex(), 16);
        try {
            srp.calculateSecret(clientEphemeralBigInteger);
        } catch (Exception ex) {
            throw new UnauthorizedException("SRP secret could not be calculated.", ex);
        }

        BigInteger clientProofBigInteger = new BigInteger(request.getClientProofHex(), 16);
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
        SessionHelper.elevateSessionToPasswordElevated(session);
        sessionRepository.save(session);
    }

    public void elevatePasswordElevatedSessionInitV1() throws IOException {
        Session session = sessionRepository.findById(getCurrentAuthenticationDetails().getAuthenticationId())
            .orElseThrow();

        SessionMultiFactorElevationRequest elevationRequest = SessionMultiFactorElevationRequestHelper.create();
        elevationRequest.setSession(session);
        sessionMultiFactorElevationRequestRepository.save(elevationRequest);

        emailSendingEngine.sendMultiFactorAuthenticationEmail(elevationRequest);
    }

    public void elevatePasswordElevatedSessionCompleteV1(ElevatePasswordElevatedSessionCompleteV1Request request) {
        String authenticationCode = request.getRequestCode();

        Session session = sessionRepository.findById(getCurrentAuthenticationDetails().getAuthenticationId())
            .orElseThrow();
        Set<SessionMultiFactorElevationRequest> sessionMultiFactorElevationRequests =
            session.getSessionMultiFactorElevationRequests();
        sessionMultiFactorElevationRequests.removeIf(ExpirationUtils::isExpiredNow);
        boolean authenticationCodeFound =
            sessionMultiFactorElevationRequests.removeIf(r -> r.getRequestCode().equals(authenticationCode));
        if (!authenticationCodeFound) {
            throw new UnauthorizedException("Authentication code not found.");
        }

        SessionHelper.elevateSessionToMultiFactorElevated(session);
        sessionRepository.save(session);
    }

    public void validateEmailAddressV1(ValidateEmailAddressV1Request request) {
        Optional<UserIdentity> userIdentityOptional =
            userIdentityRepository.findByEmailValidationKey(request.getEmailValidationKey());
        if (userIdentityOptional.isPresent()) {
            UserIdentity userIdentity = userIdentityOptional.get();
            userIdentity.setEmailValidated(true);
            userIdentityRepository.save(userIdentity);
        }
    }

    public void requestPasswordResetV1(RequestPasswordResetV1Request request) throws IOException {
        Optional<UserIdentity> userIdentityOptional =
            userIdentityRepository.findByEmailAddress(request.getEmailAddress().toLowerCase());
        if (userIdentityOptional.isPresent()) {
            UserIdentity userIdentity = userIdentityOptional.get();
            UserAuthentication userAuthentication = UserIdentityHelper.getCurrentAuthentication(userIdentity);
            UserAuthenticationResetRequest userAuthenticationResetRequest =
                UserAuthenticationResetRequestHelper.create();
            userAuthenticationResetRequest.setUserAuthentication(userAuthentication);
            userAuthenticationResetRequestRepository.save(userAuthenticationResetRequest);
            emailSendingEngine.sendPasswordResetEmail(userAuthenticationResetRequest);
        }
    }

    public void resetPasswordV1(ResetPasswordV1Request request) {
        Optional<UserAuthenticationResetRequest> userAuthenticationResetRequestOptional =
            userAuthenticationResetRequestRepository.findByRequestKey(request.getPasswordResetKey(), 3);
        if (userAuthenticationResetRequestOptional.isPresent()) {
            UserAuthenticationResetRequest userAuthenticationResetRequest =
                userAuthenticationResetRequestOptional.get();
            if (ExpirationUtils.isExpiredNow(userAuthenticationResetRequest)) {
                throw new UnauthorizedException("Password reset request expired.");
            }

            String srpSaltHex = request.getSrpSaltHex();
            String srpVerifierHex = request.getSrpVerifierHex();

            UserIdentity userIdentity = userAuthenticationResetRequest.getUserAuthentication().getUserIdentity();
            UserAuthentication newUserAuthentication = UserAuthenticationHelper.create(userIdentity,
                srpSaltHex, srpVerifierHex, request.getPasswordStretchingAlgorithm());
            userIdentity.getAuthentications().add(newUserAuthentication);

            userIdentityRepository.save(userIdentity);
            userAuthenticationResetRequestRepository.delete(userAuthenticationResetRequest);
        }
    }

    public void changePasswordV1(ChangePasswordV1Request request) {
        UserIdentity userIdentity = userIdentityRepository.findById(getCurrentUserIdentity().getId()).orElseThrow();

        String srpSaltHex = request.getSrpSaltHex();
        String srpVerifierHex = request.getSrpVerifierHex();

        UserAuthentication newUserAuthentication = UserAuthenticationHelper.create(userIdentity,
            srpSaltHex, srpVerifierHex, request.getPasswordStretchingAlgorithm());
        userIdentity.getAuthentications().add(newUserAuthentication);

        userIdentityRepository.save(userIdentity);
    }

    public GetUserIdentityV1Response getUserIdentityV1() {
        UserIdentity userIdentity = getCurrentUserIdentity();
        return new GetUserIdentityV1Response(userIdentity.getEmailAddress(), userIdentity.getFirstName(),
            userIdentity.getLastName());
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

    public UserIdentity verifyAuthenticationSessionCredentials(String authenticationSessionId) {
        AuthenticationSession authenticationSession =
            authenticationSessionRepository.findById(authenticationSessionId, 2).orElseThrow();

        if (ExpirationUtils.isExpiredNow(authenticationSession)) {
            throw new UnauthorizedException("Authentication session expired.");
        }

        return authenticationSession.getUserAuthentication().getUserIdentity();
    }

    public UserIdentity verifyDeviceCredentials(String deviceId) {
        UserDevice userDevice = userDeviceRepository.findById(deviceId).orElseThrow();
        return userDevice.getUserIdentity();
    }

    public UserIdentity verifySessionCredentials(String deviceId, String sessionId) {
        UserDevice userDevice = userDeviceRepository.findById(deviceId).orElseThrow();

        if (!userDevice.getSession().getId().equals(sessionId)) {
            throw new UnauthorizedException("Device and session are unrelated.");
        }

        if (ExpirationUtils.isExpiredNow(userDevice.getSession())) {
            throw new UnauthorizedException("Session expired.");
        }

        return userDevice.getUserIdentity();
    }

    public boolean sessionHasAssuranceLevel(String sessionId, SessionAssuranceLevel requiredAssuranceLevel) {
        Session session = sessionRepository.findById(sessionId)
            .orElseThrow(() -> new UnauthorizedException("No session found with the given ID."));

        if (ExpirationUtils.isExpiredNow(session.getAssuranceLevelExpirationTime())) {
            SessionHelper.downgradeSessionToRegular(session);
            sessionRepository.save(session);
            return requiredAssuranceLevel.equals(SessionAssuranceLevel.RegularSession);
        }

        return session.getAssuranceLevel().getNumericAssuranceLevel() >= requiredAssuranceLevel.getNumericAssuranceLevel();
    }

    public boolean authenticationSessionHasAssuranceLevel(String authenticationSessionId,
                                                          SessionAssuranceLevel requiredAssuranceLevel) {
        AuthenticationSession authenticationSession = authenticationSessionRepository.findById(authenticationSessionId)
            .orElseThrow(() -> new UnauthorizedException("No authentication session found with the given ID."));

        if (ExpirationUtils.isExpiredNow(authenticationSession.getAssuranceLevelExpirationTime())) {
            AuthenticationSessionHelper.downgradeAuthenticationSessionToPasswordElevated(authenticationSession);
            authenticationSessionRepository.save(authenticationSession);
            return requiredAssuranceLevel.equals(SessionAssuranceLevel.PasswordElevatedSession);
        }

        return authenticationSession.getAssuranceLevel().getNumericAssuranceLevel() >= requiredAssuranceLevel.getNumericAssuranceLevel();
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
