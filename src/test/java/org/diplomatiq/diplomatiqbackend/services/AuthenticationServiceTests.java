package org.diplomatiq.diplomatiqbackend.services;

import org.bouncycastle.crypto.CryptoException;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.*;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.*;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.engines.mail.EmailSendingEngine;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.BadRequestException;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqAuthenticationScheme;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationDetails;
import org.diplomatiq.diplomatiqbackend.methods.attributes.SessionAssuranceLevel;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.*;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.*;
import org.diplomatiq.diplomatiqbackend.repositories.*;
import org.diplomatiq.diplomatiqbackend.securitycontext.WithAuthenticationSessionSignatureV1;
import org.diplomatiq.diplomatiqbackend.securitycontext.WithDeviceSignatureV1;
import org.diplomatiq.diplomatiqbackend.securitycontext.WithSessionSignatureV1;
import org.diplomatiq.diplomatiqbackend.testutils.DummyData;
import org.diplomatiq.diplomatiqbackend.utils.crypto.aead.DiplomatiqAEAD;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.diplomatiq.diplomatiqbackend.utils.crypto.srp.RequestBoundaryCrossingSRP6Server;
import org.diplomatiq.diplomatiqbackend.utils.crypto.srp.SRP6Factory;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

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
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
public class AuthenticationServiceTests {
    @Autowired
    private AuthenticationService authenticationService;

    @MockBean
    private EmailSendingEngine emailSendingEngine;

    @MockBean
    private SRP6Factory srp6Factory;

    @MockBean
    private UserIdentityRepository userIdentityRepository;

    @MockBean
    private UserTemporarySRPDataRepository userTemporarySRPDataRepository;

    @MockBean
    private UserAuthenticationRepository userAuthenticationRepository;

    @MockBean
    private UserDeviceRepository userDeviceRepository;

    @MockBean
    private AuthenticationSessionRepository authenticationSessionRepository;

    @MockBean
    private AuthenticationSessionMultiFactorElevationRequestRepository authenticationSessionMultiFactorElevationRequestRepository;

    @MockBean
    private SessionMultiFactorElevationRequestRepository sessionMultiFactorElevationRequestRepository;

    @MockBean
    private SessionRepository sessionRepository;

    @MockBean
    private UserAuthenticationResetRequestRepository userAuthenticationResetRequestRepository;

    @Test
    public void getDeviceContainerKeyV1_shouldReturnDeviceContainerKey() {
        UserDevice userDevice = UserDeviceHelper.create();
        userDevice.setId("mockDeviceId");
        userDevice.setDeviceContainerKey(RandomUtils.bytes(32));
        when(userDeviceRepository.findById(userDevice.getId())).thenReturn(Optional.of(userDevice));

        GetDeviceContainerKeyV1Response response = authenticationService.getDeviceContainerKeyV1(userDevice.getId());

        verify(userDeviceRepository, times(1)).findById(userDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);

        String deviceContainerKeyBase64 = response.getDeviceContainerKeyBase64();
        byte[] deviceContainerKeyBytes = Base64.getDecoder().decode(deviceContainerKeyBase64);

        assertArrayEquals(userDevice.getDeviceContainerKey(), deviceContainerKeyBytes);
    }

    @Test
    public void getDeviceContainerKeyV1_shouldReturnMockDeviceOnNonExistingId() {
        String nonExistingDeviceId = "nonExistingDeviceId";
        when(userDeviceRepository.findById(nonExistingDeviceId)).thenReturn(Optional.empty());

        GetDeviceContainerKeyV1Response response = authenticationService.getDeviceContainerKeyV1(nonExistingDeviceId);

        verify(userDeviceRepository, times(1)).findById(nonExistingDeviceId);
        verifyNoMoreInteractions(userDeviceRepository);

        String deviceContainerKeyBase64 = response.getDeviceContainerKeyBase64();
        byte[] deviceContainerKeyBytes = Base64.getDecoder().decode(deviceContainerKeyBase64);

        assertEquals(32, deviceContainerKeyBytes.length);
    }

    @Test
    @WithDeviceSignatureV1
    public void getSessionV1_shouldReturnValidSession() throws NoSuchPaddingException, InvalidKeyException,
        NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
        IOException {
        UserDevice retrievedDevice = UserDeviceHelper.create();
        retrievedDevice.setId(DummyData.DEVICE_ID);
        when(userDeviceRepository.findById(retrievedDevice.getId())).thenReturn(Optional.of(retrievedDevice));

        Session newSession = SessionHelper.create();
        newSession.setId(DummyData.SESSION_ID);
        newSession.setUserDevice(retrievedDevice);
        when(sessionRepository.save(any(Session.class))).thenReturn(newSession);

        GetSessionV1Request getSessionV1Request = new GetSessionV1Request();
        DiplomatiqAEAD sessionTokenAead = new DiplomatiqAEAD(retrievedDevice.getSessionToken());
        byte[] sessionTokenAeadBytes = sessionTokenAead.toBytes(retrievedDevice.getDeviceKey());
        String sessionTokenAeadBase64 = Base64.getEncoder().encodeToString(sessionTokenAeadBytes);
        getSessionV1Request.setSessionTokenAeadBase64(sessionTokenAeadBase64);

        GetSessionV1Response getSessionV1Response = authenticationService.getSessionV1(getSessionV1Request);

        verify(userDeviceRepository, times(1)).findById(retrievedDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);

        ArgumentCaptor<Session> acSession = ArgumentCaptor.forClass(Session.class);
        verify(sessionRepository, times(1)).save(acSession.capture());
        verifyNoMoreInteractions(sessionRepository);

        Session savedSession = acSession.getValue();
        assertEquals(retrievedDevice, savedSession.getUserDevice());

        String sessionIdAeadBase64 = getSessionV1Response.getSessionIdAeadBase64();
        byte[] sessionIdAeadBytes = Base64.getDecoder().decode(sessionIdAeadBase64);
        DiplomatiqAEAD sessionIdAead = DiplomatiqAEAD.fromBytes(sessionIdAeadBytes, retrievedDevice.getDeviceKey());
        byte[] sessionIdBytes = sessionIdAead.getPlaintext();
        String returnedSessionId = new String(sessionIdBytes, StandardCharsets.UTF_8);

        assertEquals(newSession.getId(), returnedSessionId);
        assertEquals(SessionAssuranceLevel.RegularSession, newSession.getAssuranceLevel());
        assertEquals(newSession.getExpirationTime(), newSession.getAssuranceLevelExpirationTime());
    }

    @Test
    @WithDeviceSignatureV1
    public void getSessionV1_shouldThrowUnauthorizedIfDeviceNotFound() {
        when(userDeviceRepository.findById(DummyData.DEVICE_ID)).thenReturn(Optional.empty());

        GetSessionV1Request getSessionV1Request = new GetSessionV1Request();
        getSessionV1Request.setSessionTokenAeadBase64("dummy");
        assertThrows(UnauthorizedException.class,
            () -> authenticationService.getSessionV1(getSessionV1Request), "Could not retrieve device key.");

        verify(userDeviceRepository, times(1)).findById(DummyData.DEVICE_ID);
        verifyNoMoreInteractions(userDeviceRepository);
    }

    @Test
    @WithDeviceSignatureV1
    public void getSessionV1_shouldReturnOldSessionIfValidForAtLeastOneMinute() throws NoSuchPaddingException,
        InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException,
        IllegalBlockSizeException, InvalidKeyException {
        Session oldSession = SessionHelper.create();
        oldSession.setId(DummyData.SESSION_ID);

        UserDevice retrievedDevice = UserDeviceHelper.create();
        retrievedDevice.setId(DummyData.DEVICE_ID);
        retrievedDevice.setSession(oldSession);
        when(userDeviceRepository.findById(retrievedDevice.getId())).thenReturn(Optional.of(retrievedDevice));

        GetSessionV1Request getSessionV1Request = new GetSessionV1Request();
        getSessionV1Request.setSessionTokenAeadBase64("dummy");

        GetSessionV1Response getSessionV1Response = authenticationService.getSessionV1(getSessionV1Request);

        verify(userDeviceRepository, times(1)).findById(retrievedDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);

        String sessionIdAeadBase64 = getSessionV1Response.getSessionIdAeadBase64();
        byte[] sessionIdAeadBytes = Base64.getDecoder().decode(sessionIdAeadBase64);
        DiplomatiqAEAD sessionIdAead = DiplomatiqAEAD.fromBytes(sessionIdAeadBytes, retrievedDevice.getDeviceKey());
        byte[] sessionIdBytes = sessionIdAead.getPlaintext();
        String returnedSessionId = new String(sessionIdBytes, StandardCharsets.UTF_8);

        assertEquals(oldSession.getId(), returnedSessionId);
    }

    @Test
    @WithDeviceSignatureV1
    public void getSessionV1_shouldReturnNewSessionIfOldIsNotValidForAtLeastOneMinute() throws NoSuchPaddingException,
        InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException,
        IllegalBlockSizeException, InvalidKeyException {
        Session oldSession = SessionHelper.create();
        oldSession.setId(DummyData.SESSION_ID);
        Instant expirationTime = Instant.now().plus(Duration.ofSeconds(30));
        oldSession.setExpirationTime(expirationTime);
        oldSession.setAssuranceLevelExpirationTime(expirationTime);

        UserDevice retrievedDevice = UserDeviceHelper.create();
        retrievedDevice.setId(DummyData.DEVICE_ID);
        retrievedDevice.setSession(oldSession);
        when(userDeviceRepository.findById(retrievedDevice.getId())).thenReturn(Optional.of(retrievedDevice));

        Session newSession = SessionHelper.create();
        newSession.setId("newSessionId");
        newSession.setUserDevice(retrievedDevice);
        when(sessionRepository.save(any(Session.class))).thenReturn(newSession);

        GetSessionV1Request getSessionV1Request = new GetSessionV1Request();
        DiplomatiqAEAD sessionTokenAead = new DiplomatiqAEAD(retrievedDevice.getSessionToken());
        byte[] sessionTokenAeadBytes = sessionTokenAead.toBytes(retrievedDevice.getDeviceKey());
        String sessionTokenAeadBase64 = Base64.getEncoder().encodeToString(sessionTokenAeadBytes);
        getSessionV1Request.setSessionTokenAeadBase64(sessionTokenAeadBase64);

        GetSessionV1Response getSessionV1Response = authenticationService.getSessionV1(getSessionV1Request);

        verify(userDeviceRepository, times(1)).findById(retrievedDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);

        ArgumentCaptor<Session> acSession = ArgumentCaptor.forClass(Session.class);
        verify(sessionRepository, times(1)).delete(acSession.capture());
        verify(sessionRepository, times(1)).save(acSession.capture());
        verifyNoMoreInteractions(sessionRepository);

        Session deletedSession = acSession.getAllValues().get(0);
        assertEquals(oldSession, deletedSession);

        Session savedSession = acSession.getAllValues().get(1);
        assertEquals(retrievedDevice, savedSession.getUserDevice());

        String sessionIdAeadBase64 = getSessionV1Response.getSessionIdAeadBase64();
        byte[] sessionIdAeadBytes = Base64.getDecoder().decode(sessionIdAeadBase64);
        DiplomatiqAEAD sessionIdAead = DiplomatiqAEAD.fromBytes(sessionIdAeadBytes, retrievedDevice.getDeviceKey());
        byte[] sessionIdBytes = sessionIdAead.getPlaintext();
        String returnedSessionId = new String(sessionIdBytes, StandardCharsets.UTF_8);

        assertEquals(newSession.getId(), returnedSessionId);
        assertNotEquals(oldSession.getId(), returnedSessionId);
    }

    @Test
    @WithDeviceSignatureV1
    public void getSessionV1_shouldReturnNewSessionIfOldIsExpired() throws NoSuchPaddingException,
        InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException,
        IllegalBlockSizeException, InvalidKeyException {
        Session oldSession = SessionHelper.create();
        oldSession.setId(DummyData.SESSION_ID);
        Instant expirationTime = Instant.now().minus(Duration.ofSeconds(30));
        oldSession.setExpirationTime(expirationTime);
        oldSession.setAssuranceLevelExpirationTime(expirationTime);

        UserDevice retrievedDevice = UserDeviceHelper.create();
        retrievedDevice.setId(DummyData.DEVICE_ID);
        retrievedDevice.setSession(oldSession);
        when(userDeviceRepository.findById(retrievedDevice.getId())).thenReturn(Optional.of(retrievedDevice));

        Session newSession = SessionHelper.create();
        newSession.setId(RandomUtils.alphanumericString(32));
        newSession.setUserDevice(retrievedDevice);
        when(sessionRepository.save(any(Session.class))).thenReturn(newSession);

        GetSessionV1Request getSessionV1Request = new GetSessionV1Request();
        DiplomatiqAEAD sessionTokenAead = new DiplomatiqAEAD(retrievedDevice.getSessionToken());
        byte[] sessionTokenAeadBytes = sessionTokenAead.toBytes(retrievedDevice.getDeviceKey());
        String sessionTokenAeadBase64 = Base64.getEncoder().encodeToString(sessionTokenAeadBytes);
        getSessionV1Request.setSessionTokenAeadBase64(sessionTokenAeadBase64);

        GetSessionV1Response getSessionV1Response = authenticationService.getSessionV1(getSessionV1Request);

        verify(userDeviceRepository, times(1)).findById(retrievedDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);

        ArgumentCaptor<Session> acSession = ArgumentCaptor.forClass(Session.class);
        verify(sessionRepository, times(1)).delete(acSession.capture());
        verify(sessionRepository, times(1)).save(acSession.capture());
        verifyNoMoreInteractions(sessionRepository);

        Session deletedSession = acSession.getAllValues().get(0);
        assertEquals(oldSession, deletedSession);

        Session savedSession = acSession.getAllValues().get(1);
        assertEquals(retrievedDevice, savedSession.getUserDevice());

        String sessionIdAeadBase64 = getSessionV1Response.getSessionIdAeadBase64();
        byte[] sessionIdAeadBytes = Base64.getDecoder().decode(sessionIdAeadBase64);
        DiplomatiqAEAD sessionIdAead = DiplomatiqAEAD.fromBytes(sessionIdAeadBytes, retrievedDevice.getDeviceKey());
        byte[] sessionIdBytes = sessionIdAead.getPlaintext();
        String returnedSessionId = new String(sessionIdBytes, StandardCharsets.UTF_8);

        assertEquals(newSession.getId(), returnedSessionId);
        assertNotEquals(oldSession.getId(), returnedSessionId);
    }

    @Test
    @WithDeviceSignatureV1
    public void getSessionV1_shouldThrowUnauthorizedIfSessionTokenCannotBeDecoded() {
        UserDevice retrievedDevice = UserDeviceHelper.create();
        retrievedDevice.setId(DummyData.DEVICE_ID);
        when(userDeviceRepository.findById(retrievedDevice.getId())).thenReturn(Optional.of(retrievedDevice));

        GetSessionV1Request getSessionV1Request = new GetSessionV1Request();
        getSessionV1Request.setSessionTokenAeadBase64("surely not valid Base64");

        assertThrows(BadRequestException.class,
            () -> authenticationService.getSessionV1(getSessionV1Request), "Session token could not be decoded.");

        verify(userDeviceRepository, times(1)).findById(retrievedDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);
        verifyNoInteractions(sessionRepository);
    }

    @Test
    @WithDeviceSignatureV1
    public void getSessionV1_shouldThrowUnauthorizedIfSessionTokenCannotBeDecrypted() {
        UserDevice retrievedDevice = UserDeviceHelper.create();
        retrievedDevice.setId(DummyData.DEVICE_ID);
        when(userDeviceRepository.findById(retrievedDevice.getId())).thenReturn(Optional.of(retrievedDevice));

        String sessionTokenAeadBase64 = Base64.getEncoder().encodeToString(RandomUtils.bytes(5));

        GetSessionV1Request getSessionV1Request = new GetSessionV1Request();
        getSessionV1Request.setSessionTokenAeadBase64(sessionTokenAeadBase64);

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.getSessionV1(getSessionV1Request), "Session token could not be decrypted.");

        verify(userDeviceRepository, times(1)).findById(retrievedDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);
        verifyNoInteractions(sessionRepository);
    }

    @Test
    @WithDeviceSignatureV1
    public void getSessionV1_shouldThrowUnauthorizedIfSessionTokenAndDeviceAreUnrelated() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        UserDevice retrievedDevice = UserDeviceHelper.create();
        retrievedDevice.setId(DummyData.DEVICE_ID);
        when(userDeviceRepository.findById(retrievedDevice.getId())).thenReturn(Optional.of(retrievedDevice));

        byte[] sessionToken = RandomUtils.bytes(32);
        DiplomatiqAEAD sessionTokenAead = new DiplomatiqAEAD(sessionToken);
        byte[] sessionTokenAeadBytes = sessionTokenAead.toBytes(retrievedDevice.getDeviceKey());
        String sessionTokenAeadBase64 = Base64.getEncoder().encodeToString(sessionTokenAeadBytes);

        GetSessionV1Request getSessionV1Request = new GetSessionV1Request();
        getSessionV1Request.setSessionTokenAeadBase64(sessionTokenAeadBase64);

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.getSessionV1(getSessionV1Request), "Session token and device are unrelated.");

        verify(userDeviceRepository, times(1)).findById(retrievedDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);
        verifyNoInteractions(sessionRepository);
    }

    @Test
    @WithAuthenticationSessionSignatureV1
    public void loginV1_shouldLogin() throws NoSuchPaddingException, InvalidAlgorithmParameterException,
        NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        UserIdentity userIdentity =
            UserIdentityHelper.create(DummyData.USER_EMAIL,
                DummyData.USER_FIRST_NAME,
                DummyData.USER_LAST_NAME);

        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, "", "",
            PasswordStretchingAlgorithm.Scrypt_v1);
        userAuthentication.setUserIdentity(userIdentity);

        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(RandomUtils.bytes(32));
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);
        authenticationSession.setUserAuthentication(userAuthentication);

        when(authenticationSessionRepository.findById(authenticationSession.getId(), 2))
            .thenReturn(Optional.of(authenticationSession));

        UserDevice userDevice = UserDeviceHelper.create();
        userDevice.setId(DummyData.DEVICE_ID);
        userDevice.setUserIdentity(userIdentity);
        when(userDeviceRepository.save(any(UserDevice.class))).thenReturn(userDevice);

        LoginV1Response loginV1Response = authenticationService.loginV1();

        verify(authenticationSessionRepository, times(1)).findById(authenticationSession.getId(), 2);
        verifyNoMoreInteractions(authenticationSessionRepository);

        ArgumentCaptor<UserDevice> acUserDevice = ArgumentCaptor.forClass(UserDevice.class);
        verify(userDeviceRepository, times(1)).save(acUserDevice.capture());
        verifyNoMoreInteractions(userDeviceRepository);

        UserDevice savedUserDevice = acUserDevice.getValue();
        assertEquals(userIdentity.getEmailAddress(), savedUserDevice.getUserIdentity().getEmailAddress());

        String deviceIdAeadBase64 = loginV1Response.getDeviceIdAeadBase64();
        byte[] deviceIdAeadBytes = Base64.getDecoder().decode(deviceIdAeadBase64);
        DiplomatiqAEAD deviceIdAead = DiplomatiqAEAD.fromBytes(deviceIdAeadBytes, userDevice.getDeviceKey());
        byte[] sessionIdBytes = deviceIdAead.getPlaintext();
        String returnedDeviceId = new String(sessionIdBytes, StandardCharsets.UTF_8);

        String deviceKeyAeadBase64 = loginV1Response.getDeviceKeyAeadBase64();
        byte[] deviceKeyAeadBytes = Base64.getDecoder().decode(deviceKeyAeadBase64);
        DiplomatiqAEAD deviceKeyAead = DiplomatiqAEAD.fromBytes(deviceKeyAeadBytes,
            authenticationSession.getAuthenticationSessionKey());
        byte[] returnedDeviceKey = deviceKeyAead.getPlaintext();

        String sessionTokenAeadBase64 = loginV1Response.getSessionTokenAeadBase64();
        byte[] sessionTokenAeadBytes = Base64.getDecoder().decode(sessionTokenAeadBase64);
        DiplomatiqAEAD sessionTokenAead = DiplomatiqAEAD.fromBytes(sessionTokenAeadBytes, userDevice.getDeviceKey());
        byte[] returnedSessionToken = sessionTokenAead.getPlaintext();

        assertEquals(userDevice.getId(), returnedDeviceId);
        assertArrayEquals(userDevice.getDeviceKey(), returnedDeviceKey);
        assertArrayEquals(userDevice.getSessionToken(), returnedSessionToken);
    }

    @Test
    @WithDeviceSignatureV1
    public void logoutV1_shouldLogout() {
        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);

        UserDevice userDevice = UserDeviceHelper.create();
        userDevice.setId(DummyData.DEVICE_ID);
        userDevice.setSession(session);

        when(userDeviceRepository.findById(userDevice.getId())).thenReturn(Optional.of(userDevice));

        authenticationService.logoutV1();

        verify(userDeviceRepository, times(1)).findById(userDevice.getId());

        ArgumentCaptor<UserDevice> acUserDevice = ArgumentCaptor.forClass(UserDevice.class);
        verify(userDeviceRepository).delete(acUserDevice.capture());
        verifyNoMoreInteractions(userDeviceRepository);
        UserDevice deletedUserDevice = acUserDevice.getValue();
        assertEquals(userDevice, deletedUserDevice);

        ArgumentCaptor<Session> acSession = ArgumentCaptor.forClass(Session.class);
        verify(sessionRepository).delete(acSession.capture());
        verifyNoMoreInteractions(sessionRepository);
        Session deletedSession = acSession.getValue();
        assertEquals(session, deletedSession);
    }

    @Test
    public void passwordAuthenticationInitV1_shouldInitPasswordAuthentication() throws NoSuchAlgorithmException {
        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        BigInteger srpSaltBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpSaltHex = srpSaltBigInteger.toString(16);
        BigInteger srpVerifierBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpVerifierHex = srpVerifierBigInteger.toString(16);

        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;
        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, srpSaltHex,
            srpVerifierHex, passwordStretchingAlgorithm);
        userIdentity.setAuthentications(Set.of(userAuthentication));

        when(userIdentityRepository.findByEmailAddress(userIdentity.getEmailAddress(), 2))
            .thenReturn(Optional.of(userIdentity));

        RequestBoundaryCrossingSRP6Server srp6Server = mock(RequestBoundaryCrossingSRP6Server.class);
        when(srp6Factory.getSrp6Server(srpVerifierBigInteger)).thenReturn(srp6Server);

        BigInteger serverEphemeralBigInteger = BigInteger.valueOf(26);
        String serverEphemeralHex = serverEphemeralBigInteger.toString(16);
        when(srp6Server.generateServerCredentials()).thenReturn(serverEphemeralBigInteger);

        BigInteger serverSecretBigInteger = BigInteger.valueOf(42);
        String serverSecretHex = serverSecretBigInteger.toString(16);
        when(srp6Server.getb()).thenReturn(serverSecretBigInteger);

        PasswordAuthenticationInitV1Request request = new PasswordAuthenticationInitV1Request();
        request.setEmailAddress(userIdentity.getEmailAddress());

        PasswordAuthenticationInitV1Response response = authenticationService.passwordAuthenticationInitV1(request);

        verify(userIdentityRepository, times(1)).findByEmailAddress(userIdentity.getEmailAddress(), 2);
        verify(srp6Factory, times(1)).getSrp6Server(srpVerifierBigInteger);
        verify(srp6Server, times(1)).generateServerCredentials();
        verify(srp6Server, times(1)).getb();

        ArgumentCaptor<UserIdentity> acUserIdentity = ArgumentCaptor.forClass(UserIdentity.class);
        verify(userIdentityRepository, times(1)).save(acUserIdentity.capture());

        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(srp6Factory);
        verifyNoMoreInteractions(srp6Server);

        UserIdentity savedUserIdentity = acUserIdentity.getValue();
        UserAuthentication currentAuthentication = UserIdentityHelper.getCurrentAuthentication(savedUserIdentity);
        Set<UserTemporarySRPData> userTemporarySRPDatas = currentAuthentication.getUserTemporarySrpDatas();
        assertEquals(1, userTemporarySRPDatas.size());

        UserTemporarySRPData savedUserTemporarySrpData = userTemporarySRPDatas.iterator().next();
        assertEquals(serverEphemeralHex, savedUserTemporarySrpData.getServerEphemeralHex());
        assertEquals(serverSecretHex, savedUserTemporarySrpData.getServerSecretHex());

        assertEquals(serverEphemeralHex, response.getServerEphemeralHex());
        assertEquals(srpSaltHex, response.getSrpSaltHex());
        assertEquals(passwordStretchingAlgorithm, response.getPasswordStretchingAlgorithm());
    }

    @Test
    public void passwordAuthenticationInitV1_shouldNotThrowIfUserNotExists() {
        when(userIdentityRepository.findByEmailAddress(DummyData.USER_EMAIL, 2)).thenReturn(Optional.empty());
        when(srp6Factory.getSrp6Server(any(BigInteger.class))).thenCallRealMethod();
        when(srp6Factory.getSrp6VerifierGenerator()).thenCallRealMethod();

        PasswordAuthenticationInitV1Request request = new PasswordAuthenticationInitV1Request();
        request.setEmailAddress(DummyData.USER_EMAIL);

        PasswordAuthenticationInitV1Response response =
            assertDoesNotThrow(() -> authenticationService.passwordAuthenticationInitV1(request));

        verify(userIdentityRepository, times(1)).findByEmailAddress(DummyData.USER_EMAIL, 2);
        verify(srp6Factory, times(1)).getSrp6Server(any(BigInteger.class));
        verify(srp6Factory, times(1)).getSrp6VerifierGenerator();
        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(srp6Factory);

        assertNotNull(response.getSrpSaltHex());
        assertNotNull(response.getServerEphemeralHex());
        assertNotNull(response.getPasswordStretchingAlgorithm());
    }

    @Test
    public void passwordAuthenticationCompleteV1_shouldCreateAuthenticationSession() throws NoSuchPaddingException,
        InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
        InvalidKeyException, IOException, CryptoException {
        BigInteger srpClientEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientEphemeralHex = srpClientEphemeralBigInteger.toString(16);

        BigInteger srpClientProofBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientProofHex = srpClientProofBigInteger.toString(16);

        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        BigInteger srpSaltBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpSaltHex = srpSaltBigInteger.toString(16);
        BigInteger srpVerifierBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpVerifierHex = srpVerifierBigInteger.toString(16);
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;
        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, srpSaltHex,
            srpVerifierHex, passwordStretchingAlgorithm);
        userIdentity.setAuthentications(Set.of(userAuthentication));

        byte[] authenticationSessionKey = RandomUtils.bytes(32);
        BigInteger authenticationSessionKeyBigInteger = new BigInteger(1, authenticationSessionKey);
        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(authenticationSessionKey);
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);
        authenticationSession.setUserAuthentication(userAuthentication);

        BigInteger serverEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String serverEphemeralHex = serverEphemeralBigInteger.toString(16);
        BigInteger serverSecretBigInteger = new BigInteger(RandomUtils.numericString(10));
        String serverSecretHex = serverSecretBigInteger.toString(16);

        UserTemporarySRPData userTemporarySRPData = UserTemporarySRPDataHelper.create(serverEphemeralHex,
            serverSecretHex);
        userAuthentication.setUserTemporarySrpDatas(new HashSet<>(Collections.singletonList(userTemporarySRPData)));

        when(userIdentityRepository.findByEmailAddress(userIdentity.getEmailAddress(), 2))
            .thenReturn(Optional.of(userIdentity));

        RequestBoundaryCrossingSRP6Server srp6Server = mock(RequestBoundaryCrossingSRP6Server.class);
        when(srp6Factory.getSrp6Server(srpVerifierBigInteger)).thenReturn(srp6Server);

        when(srp6Server.verifyClientEvidenceMessage(srpClientProofBigInteger)).thenReturn(true);
        when(srp6Server.calculateSessionKey()).thenReturn(authenticationSessionKeyBigInteger);

        when(authenticationSessionRepository.save(any(AuthenticationSession.class))).then(invocationOnMock -> {
            AuthenticationSession savedAuthenticationSession = invocationOnMock.getArgument(0);
            savedAuthenticationSession.setId(authenticationSession.getId());
            return savedAuthenticationSession;
        });

        PasswordAuthenticationCompleteV1Request request = new PasswordAuthenticationCompleteV1Request();
        request.setEmailAddress(userIdentity.getEmailAddress());
        request.setClientEphemeralHex(srpClientEphemeralHex);
        request.setClientProofHex(srpClientProofHex);
        request.setServerEphemeralHex(serverEphemeralHex);

        PasswordAuthenticationCompleteV1Response response =
            authenticationService.passwordAuthenticationCompleteV1(request);

        verify(userIdentityRepository, times(1)).findByEmailAddress(userIdentity.getEmailAddress(), 2);
        verify(srp6Factory, times(1)).getSrp6Server(srpVerifierBigInteger);
        verify(srp6Server, times(1)).setb(new BigInteger(serverSecretHex, 16));
        verify(srp6Server, times(1)).setB(new BigInteger(serverEphemeralHex, 16));

        ArgumentCaptor<UserTemporarySRPData> acUserTemporarySrpData =
            ArgumentCaptor.forClass(UserTemporarySRPData.class);
        verify(userTemporarySRPDataRepository, times(1)).delete(acUserTemporarySrpData.capture());

        UserTemporarySRPData deletedUserTemporarySrpData = acUserTemporarySrpData.getValue();
        assertEquals(serverEphemeralHex, deletedUserTemporarySrpData.getServerEphemeralHex());
        assertEquals(serverSecretHex, deletedUserTemporarySrpData.getServerSecretHex());

        verify(srp6Server, times(1)).calculateSecret(srpClientEphemeralBigInteger);
        verify(srp6Server, times(1)).verifyClientEvidenceMessage(srpClientProofBigInteger);
        verify(srp6Server, times(1)).calculateServerEvidenceMessage();
        verify(srp6Server, times(1)).calculateSessionKey();

        ArgumentCaptor<AuthenticationSession> acAuthenticationSession =
            ArgumentCaptor.forClass(AuthenticationSession.class);
        verify(authenticationSessionRepository, times(1)).save(acAuthenticationSession.capture());

        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(srp6Factory);
        verifyNoMoreInteractions(srp6Server);
        verifyNoMoreInteractions(authenticationSessionRepository);

        AuthenticationSession savedAuthenticationSession = acAuthenticationSession.getValue();
        UserAuthentication currentAuthentication = savedAuthenticationSession.getUserAuthentication();
        Set<UserTemporarySRPData> userTemporarySRPDatas = currentAuthentication.getUserTemporarySrpDatas();
        assertEquals(0, userTemporarySRPDatas.size());

        String authenticationSessionIdAeadBase64 = response.getAuthenticationSessionIdAeadBase64();
        byte[] authenticationSessionIdAeadBytes = Base64.getDecoder().decode(authenticationSessionIdAeadBase64);
        DiplomatiqAEAD authenticationSessionIdAead = DiplomatiqAEAD.fromBytes(authenticationSessionIdAeadBytes,
            authenticationSessionKey);
        byte[] authenticationSessionIdBytes = authenticationSessionIdAead.getPlaintext();
        String authenticationSessionId = new String(authenticationSessionIdBytes, StandardCharsets.UTF_8);

        assertEquals(authenticationSession.getId(), authenticationSessionId);
    }

    @Test
    public void passwordAuthenticationCompleteV1_shouldNotCreateAuthenticationSessionIfPreviousServerEphemeralNotFound() {
        BigInteger srpClientEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientEphemeralHex = srpClientEphemeralBigInteger.toString(16);

        BigInteger srpClientProofBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientProofHex = srpClientProofBigInteger.toString(16);

        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        BigInteger srpSaltBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpSaltHex = srpSaltBigInteger.toString(16);
        BigInteger srpVerifierBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpVerifierHex = srpVerifierBigInteger.toString(16);
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;
        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, srpSaltHex,
            srpVerifierHex, passwordStretchingAlgorithm);
        userIdentity.setAuthentications(Set.of(userAuthentication));

        BigInteger serverEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String serverEphemeralHex = serverEphemeralBigInteger.toString(16);

        when(userIdentityRepository.findByEmailAddress(userIdentity.getEmailAddress(), 2))
            .thenReturn(Optional.of(userIdentity));

        RequestBoundaryCrossingSRP6Server srp6Server = mock(RequestBoundaryCrossingSRP6Server.class);
        when(srp6Factory.getSrp6Server(srpVerifierBigInteger)).thenReturn(srp6Server);

        PasswordAuthenticationCompleteV1Request request = new PasswordAuthenticationCompleteV1Request();
        request.setEmailAddress(userIdentity.getEmailAddress());
        request.setClientEphemeralHex(srpClientEphemeralHex);
        request.setClientProofHex(srpClientProofHex);
        request.setServerEphemeralHex(serverEphemeralHex);

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.passwordAuthenticationCompleteV1(request), "Previous, still valid server " +
                "ephemeral value not found.");

        verify(userIdentityRepository, times(1)).findByEmailAddress(userIdentity.getEmailAddress(), 2);
        verify(srp6Factory, times(1)).getSrp6Server(srpVerifierBigInteger);
        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(srp6Factory);
        verifyNoInteractions(srp6Server);
        verifyNoInteractions(authenticationSessionRepository);
    }

    @Test
    public void passwordAuthenticationCompleteV1_shouldNotCreateAuthenticationSessionIfClientProofCannotBeVerified() throws CryptoException {
        BigInteger srpClientEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientEphemeralHex = srpClientEphemeralBigInteger.toString(16);

        BigInteger srpClientProofBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientProofHex = srpClientProofBigInteger.toString(16);

        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        BigInteger srpSaltBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpSaltHex = srpSaltBigInteger.toString(16);
        BigInteger srpVerifierBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpVerifierHex = srpVerifierBigInteger.toString(16);
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;
        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, srpSaltHex,
            srpVerifierHex, passwordStretchingAlgorithm);
        userIdentity.setAuthentications(Set.of(userAuthentication));

        byte[] authenticationSessionKey = RandomUtils.bytes(32);
        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(authenticationSessionKey);
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);
        authenticationSession.setUserAuthentication(userAuthentication);

        BigInteger serverEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String serverEphemeralHex = serverEphemeralBigInteger.toString(16);
        BigInteger serverSecretBigInteger = new BigInteger(RandomUtils.numericString(10));
        String serverSecretHex = serverSecretBigInteger.toString(16);

        UserTemporarySRPData userTemporarySRPData = UserTemporarySRPDataHelper.create(serverEphemeralHex,
            serverSecretHex);
        userAuthentication.setUserTemporarySrpDatas(new HashSet<>(Collections.singletonList(userTemporarySRPData)));

        when(userIdentityRepository.findByEmailAddress(userIdentity.getEmailAddress(), 2))
            .thenReturn(Optional.of(userIdentity));

        RequestBoundaryCrossingSRP6Server srp6Server = mock(RequestBoundaryCrossingSRP6Server.class);
        when(srp6Factory.getSrp6Server(srpVerifierBigInteger)).thenReturn(srp6Server);

        when(srp6Server.verifyClientEvidenceMessage(srpClientProofBigInteger)).thenReturn(false);

        PasswordAuthenticationCompleteV1Request request = new PasswordAuthenticationCompleteV1Request();
        request.setEmailAddress(userIdentity.getEmailAddress());
        request.setClientEphemeralHex(srpClientEphemeralHex);
        request.setClientProofHex(srpClientProofHex);
        request.setServerEphemeralHex(serverEphemeralHex);

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.passwordAuthenticationCompleteV1(request), "Client proof could not be " +
                "verified.");

        verify(userIdentityRepository, times(1)).findByEmailAddress(userIdentity.getEmailAddress(), 2);
        verify(srp6Factory, times(1)).getSrp6Server(srpVerifierBigInteger);
        verify(srp6Server, times(1)).setb(new BigInteger(serverSecretHex, 16));
        verify(srp6Server, times(1)).setB(new BigInteger(serverEphemeralHex, 16));

        ArgumentCaptor<UserTemporarySRPData> acUserTemporarySrpData =
            ArgumentCaptor.forClass(UserTemporarySRPData.class);
        verify(userTemporarySRPDataRepository, times(1)).delete(acUserTemporarySrpData.capture());

        UserTemporarySRPData deletedUserTemporarySrpData = acUserTemporarySrpData.getValue();
        assertEquals(serverEphemeralHex, deletedUserTemporarySrpData.getServerEphemeralHex());
        assertEquals(serverSecretHex, deletedUserTemporarySrpData.getServerSecretHex());

        verify(srp6Server, times(1)).calculateSecret(srpClientEphemeralBigInteger);
        verify(srp6Server, times(1)).verifyClientEvidenceMessage(srpClientProofBigInteger);

        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(srp6Factory);
        verifyNoMoreInteractions(srp6Server);
        verifyNoInteractions(authenticationSessionRepository);
    }

    @Test
    @WithAuthenticationSessionSignatureV1
    public void elevateAuthenticationSessionInitV1_shouldSendElevationEmail() throws IOException {
        byte[] authenticationSessionKey = RandomUtils.bytes(32);
        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(authenticationSessionKey);
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);

        when(authenticationSessionRepository.findById(authenticationSession.getId()))
            .thenReturn(Optional.of(authenticationSession));

        authenticationService.elevateAuthenticationSessionInitV1();

        verify(authenticationSessionRepository, times(1)).findById(authenticationSession.getId());

        ArgumentCaptor<AuthenticationSessionMultiFactorElevationRequest> acAuthenticationSessionMultiFactorElevationRequestArgumentCaptor =
            ArgumentCaptor.forClass(AuthenticationSessionMultiFactorElevationRequest.class);
        verify(authenticationSessionMultiFactorElevationRequestRepository, times(1))
            .save(acAuthenticationSessionMultiFactorElevationRequestArgumentCaptor.capture());

        AuthenticationSessionMultiFactorElevationRequest authenticationSessionMultiFactorElevationRequest =
            acAuthenticationSessionMultiFactorElevationRequestArgumentCaptor.getValue();
        assertEquals(authenticationSession,
            authenticationSessionMultiFactorElevationRequest.getAuthenticationSession());

        verify(emailSendingEngine, times(1)).sendMultiFactorAuthenticationEmail(authenticationSessionMultiFactorElevationRequest);
    }

    @Test
    @WithAuthenticationSessionSignatureV1
    public void elevateAuthenticationSessionCompleteV1_shouldElevateAuthenticationSession() throws IOException {
        byte[] authenticationSessionKey = RandomUtils.bytes(32);
        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(authenticationSessionKey);
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);

        AuthenticationSessionMultiFactorElevationRequest authenticationSessionMultiFactorElevationRequest =
            AuthenticationSessionMultiFactorElevationRequestHelper.create();

        authenticationSession.setAuthenticationSessionMultiFactorElevationRequests(
            new HashSet<>(Collections.singletonList(authenticationSessionMultiFactorElevationRequest))
        );

        when(authenticationSessionRepository.findById(authenticationSession.getId()))
            .thenReturn(Optional.of(authenticationSession));

        ElevateAuthenticationSessionCompleteV1Request request = new ElevateAuthenticationSessionCompleteV1Request();
        request.setRequestCode(authenticationSessionMultiFactorElevationRequest.getRequestCode());

        authenticationService.elevateAuthenticationSessionCompleteV1(request);

        verify(authenticationSessionRepository, times(1)).findById(authenticationSession.getId());

        ArgumentCaptor<AuthenticationSession> acAuthenticationSession =
            ArgumentCaptor.forClass(AuthenticationSession.class);
        verify(authenticationSessionRepository, times(1)).save(acAuthenticationSession.capture());
        verifyNoMoreInteractions(authenticationSessionRepository);

        AuthenticationSession savedAuthenticationSession = acAuthenticationSession.getValue();
        assertEquals(SessionAssuranceLevel.MultiFactorElevatedSession, savedAuthenticationSession.getAssuranceLevel());
        assertEquals(0, savedAuthenticationSession.getAuthenticationSessionMultiFactorElevationRequests().size());
    }

    @Test
    @WithAuthenticationSessionSignatureV1
    public void elevateAuthenticationSessionCompleteV1_shouldNotElevateAuthenticationSessionWithInvalidCode() throws IOException {
        byte[] authenticationSessionKey = RandomUtils.bytes(32);
        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(authenticationSessionKey);
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);

        AuthenticationSessionMultiFactorElevationRequest authenticationSessionMultiFactorElevationRequest =
            AuthenticationSessionMultiFactorElevationRequestHelper.create();

        authenticationSession.setAuthenticationSessionMultiFactorElevationRequests(
            new HashSet<>(Collections.singletonList(authenticationSessionMultiFactorElevationRequest))
        );

        when(authenticationSessionRepository.findById(authenticationSession.getId()))
            .thenReturn(Optional.of(authenticationSession));

        ElevateAuthenticationSessionCompleteV1Request request = new ElevateAuthenticationSessionCompleteV1Request();
        request.setRequestCode("invalidCode");

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.elevateAuthenticationSessionCompleteV1(request), "Authentication code not " +
                "found.");

        verify(authenticationSessionRepository, times(1)).findById(authenticationSession.getId());
        verifyNoMoreInteractions(authenticationSessionRepository);
    }

    @Test
    @WithSessionSignatureV1
    public void elevateRegularSessionInitV1_shouldInitPasswordAuthentication() {
        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        BigInteger srpSaltBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpSaltHex = srpSaltBigInteger.toString(16);
        BigInteger srpVerifierBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpVerifierHex = srpVerifierBigInteger.toString(16);

        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;
        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, srpSaltHex,
            srpVerifierHex, passwordStretchingAlgorithm);
        userIdentity.setAuthentications(Set.of(userAuthentication));

        when(userIdentityRepository.findById(userIdentity.getId(), 2))
            .thenReturn(Optional.of(userIdentity));

        RequestBoundaryCrossingSRP6Server srp6Server = mock(RequestBoundaryCrossingSRP6Server.class);
        when(srp6Factory.getSrp6Server(srpVerifierBigInteger)).thenReturn(srp6Server);

        BigInteger serverEphemeralBigInteger = BigInteger.valueOf(26);
        String serverEphemeralHex = serverEphemeralBigInteger.toString(16);
        when(srp6Server.generateServerCredentials()).thenReturn(serverEphemeralBigInteger);

        BigInteger serverSecretBigInteger = BigInteger.valueOf(42);
        String serverSecretHex = serverSecretBigInteger.toString(16);
        when(srp6Server.getb()).thenReturn(serverSecretBigInteger);

        ElevateRegularSessionInitV1Response response = authenticationService.elevateRegularSessionInitV1();

        verify(userIdentityRepository, times(1)).findById(userIdentity.getId(), 2);
        verify(srp6Factory, times(1)).getSrp6Server(srpVerifierBigInteger);
        verify(srp6Server, times(1)).generateServerCredentials();
        verify(srp6Server, times(1)).getb();

        ArgumentCaptor<UserIdentity> acUserIdentity = ArgumentCaptor.forClass(UserIdentity.class);
        verify(userIdentityRepository, times(1)).save(acUserIdentity.capture());

        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(srp6Factory);
        verifyNoMoreInteractions(srp6Server);

        UserIdentity savedUserIdentity = acUserIdentity.getValue();
        UserAuthentication currentAuthentication = UserIdentityHelper.getCurrentAuthentication(savedUserIdentity);
        Set<UserTemporarySRPData> userTemporarySRPDatas = currentAuthentication.getUserTemporarySrpDatas();
        assertEquals(1, userTemporarySRPDatas.size());

        UserTemporarySRPData savedUserTemporarySrpData = userTemporarySRPDatas.iterator().next();
        assertEquals(serverEphemeralHex, savedUserTemporarySrpData.getServerEphemeralHex());
        assertEquals(serverSecretHex, savedUserTemporarySrpData.getServerSecretHex());

        assertEquals(serverEphemeralHex, response.getServerEphemeralHex());
        assertEquals(srpSaltHex, response.getSrpSaltHex());
        assertEquals(passwordStretchingAlgorithm, response.getPasswordStretchingAlgorithm());
    }

    @Test
    @WithSessionSignatureV1
    public void elevateRegularSessionCompleteV1_shouldElevateSession() throws CryptoException {
        BigInteger srpClientEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientEphemeralHex = srpClientEphemeralBigInteger.toString(16);

        BigInteger srpClientProofBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientProofHex = srpClientProofBigInteger.toString(16);

        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        BigInteger srpSaltBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpSaltHex = srpSaltBigInteger.toString(16);
        BigInteger srpVerifierBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpVerifierHex = srpVerifierBigInteger.toString(16);
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;
        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, srpSaltHex,
            srpVerifierHex, passwordStretchingAlgorithm);
        userIdentity.setAuthentications(Set.of(userAuthentication));

        BigInteger serverEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String serverEphemeralHex = serverEphemeralBigInteger.toString(16);
        BigInteger serverSecretBigInteger = new BigInteger(RandomUtils.numericString(10));
        String serverSecretHex = serverSecretBigInteger.toString(16);

        UserTemporarySRPData userTemporarySRPData = UserTemporarySRPDataHelper.create(serverEphemeralHex,
            serverSecretHex);
        userAuthentication.setUserTemporarySrpDatas(new HashSet<>(Collections.singletonList(userTemporarySRPData)));

        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);

        when(userIdentityRepository.findById(userIdentity.getId(), 2))
            .thenReturn(Optional.of(userIdentity));

        RequestBoundaryCrossingSRP6Server srp6Server = mock(RequestBoundaryCrossingSRP6Server.class);
        when(srp6Factory.getSrp6Server(srpVerifierBigInteger)).thenReturn(srp6Server);

        when(srp6Server.verifyClientEvidenceMessage(srpClientProofBigInteger)).thenReturn(true);

        when(sessionRepository.findById(session.getId())).thenReturn(Optional.of(session));

        ElevateRegularSessionCompleteV1Request request = new ElevateRegularSessionCompleteV1Request();
        request.setClientEphemeralHex(srpClientEphemeralHex);
        request.setClientProofHex(srpClientProofHex);
        request.setServerEphemeralHex(serverEphemeralHex);

        authenticationService.elevateRegularSessionCompleteV1(request);

        verify(userIdentityRepository, times(1)).findById(userIdentity.getId(), 2);
        verify(srp6Factory, times(1)).getSrp6Server(srpVerifierBigInteger);
        verify(srp6Server, times(1)).setb(new BigInteger(serverSecretHex, 16));
        verify(srp6Server, times(1)).setB(new BigInteger(serverEphemeralHex, 16));

        ArgumentCaptor<UserTemporarySRPData> acUserTemporarySrpData =
            ArgumentCaptor.forClass(UserTemporarySRPData.class);
        verify(userTemporarySRPDataRepository, times(1)).delete(acUserTemporarySrpData.capture());

        UserTemporarySRPData deletedUserTemporarySrpData = acUserTemporarySrpData.getValue();
        assertEquals(serverEphemeralHex, deletedUserTemporarySrpData.getServerEphemeralHex());
        assertEquals(serverSecretHex, deletedUserTemporarySrpData.getServerSecretHex());

        verify(srp6Server, times(1)).calculateSecret(srpClientEphemeralBigInteger);
        verify(srp6Server, times(1)).verifyClientEvidenceMessage(srpClientProofBigInteger);

        verify(sessionRepository, times(1)).findById(session.getId());

        ArgumentCaptor<Session> acSession = ArgumentCaptor.forClass(Session.class);
        verify(sessionRepository, times(1)).save(acSession.capture());

        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(srp6Factory);
        verifyNoMoreInteractions(srp6Server);
        verifyNoMoreInteractions(sessionRepository);

        Session savedSession = acSession.getValue();
        assertEquals(SessionAssuranceLevel.PasswordElevatedSession, savedSession.getAssuranceLevel());
    }

    @Test
    @WithSessionSignatureV1
    public void elevateRegularSessionCompleteV1_shouldNotElevateSessionIfPreviousServerEphemeralNotFound() throws CryptoException {
        BigInteger srpClientEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientEphemeralHex = srpClientEphemeralBigInteger.toString(16);

        BigInteger srpClientProofBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientProofHex = srpClientProofBigInteger.toString(16);

        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        BigInteger srpSaltBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpSaltHex = srpSaltBigInteger.toString(16);
        BigInteger srpVerifierBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpVerifierHex = srpVerifierBigInteger.toString(16);
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;
        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, srpSaltHex,
            srpVerifierHex, passwordStretchingAlgorithm);
        userIdentity.setAuthentications(Set.of(userAuthentication));

        BigInteger serverEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String serverEphemeralHex = serverEphemeralBigInteger.toString(16);
        BigInteger serverSecretBigInteger = new BigInteger(RandomUtils.numericString(10));

        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);

        when(userIdentityRepository.findById(userIdentity.getId(), 2))
            .thenReturn(Optional.of(userIdentity));

        RequestBoundaryCrossingSRP6Server srp6Server = mock(RequestBoundaryCrossingSRP6Server.class);
        when(srp6Factory.getSrp6Server(srpVerifierBigInteger)).thenReturn(srp6Server);

        when(srp6Server.verifyClientEvidenceMessage(srpClientProofBigInteger)).thenReturn(true);

        when(sessionRepository.findById(session.getId())).thenReturn(Optional.of(session));

        ElevateRegularSessionCompleteV1Request request = new ElevateRegularSessionCompleteV1Request();
        request.setClientEphemeralHex(srpClientEphemeralHex);
        request.setClientProofHex(srpClientProofHex);
        request.setServerEphemeralHex(serverEphemeralHex);

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.elevateRegularSessionCompleteV1(request), "Previous, still valid server " +
                "ephemeral value not found.");

        verify(userIdentityRepository, times(1)).findById(userIdentity.getId(), 2);
        verify(srp6Factory, times(1)).getSrp6Server(srpVerifierBigInteger);
        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(srp6Factory);
        verifyNoInteractions(srp6Server);
        verifyNoInteractions(sessionRepository);
    }

    @Test
    @WithSessionSignatureV1
    public void elevateRegularSessionCompleteV1_shouldNotElevateSessionIfClientProofCannotBeVerified() throws CryptoException {
        BigInteger srpClientEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientEphemeralHex = srpClientEphemeralBigInteger.toString(16);

        BigInteger srpClientProofBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpClientProofHex = srpClientProofBigInteger.toString(16);

        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        BigInteger srpSaltBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpSaltHex = srpSaltBigInteger.toString(16);
        BigInteger srpVerifierBigInteger = new BigInteger(RandomUtils.numericString(10));
        String srpVerifierHex = srpVerifierBigInteger.toString(16);
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;
        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, srpSaltHex,
            srpVerifierHex, passwordStretchingAlgorithm);
        userIdentity.setAuthentications(Set.of(userAuthentication));

        BigInteger serverEphemeralBigInteger = new BigInteger(RandomUtils.numericString(10));
        String serverEphemeralHex = serverEphemeralBigInteger.toString(16);
        BigInteger serverSecretBigInteger = new BigInteger(RandomUtils.numericString(10));
        String serverSecretHex = serverSecretBigInteger.toString(16);

        UserTemporarySRPData userTemporarySRPData = UserTemporarySRPDataHelper.create(serverEphemeralHex,
            serverSecretHex);
        userAuthentication.setUserTemporarySrpDatas(new HashSet<>(Collections.singletonList(userTemporarySRPData)));

        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);

        when(userIdentityRepository.findById(userIdentity.getId(), 2))
            .thenReturn(Optional.of(userIdentity));

        RequestBoundaryCrossingSRP6Server srp6Server = mock(RequestBoundaryCrossingSRP6Server.class);
        when(srp6Factory.getSrp6Server(srpVerifierBigInteger)).thenReturn(srp6Server);

        when(srp6Server.verifyClientEvidenceMessage(srpClientProofBigInteger)).thenReturn(false);

        ElevateRegularSessionCompleteV1Request request = new ElevateRegularSessionCompleteV1Request();
        request.setClientEphemeralHex(srpClientEphemeralHex);
        request.setClientProofHex(srpClientProofHex);
        request.setServerEphemeralHex(serverEphemeralHex);

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.elevateRegularSessionCompleteV1(request), "Client proof could not be " +
                "verified.");

        verify(userIdentityRepository, times(1)).findById(userIdentity.getId(), 2);
        verify(srp6Factory, times(1)).getSrp6Server(srpVerifierBigInteger);
        verify(srp6Server, times(1)).setb(new BigInteger(serverSecretHex, 16));
        verify(srp6Server, times(1)).setB(new BigInteger(serverEphemeralHex, 16));

        ArgumentCaptor<UserTemporarySRPData> acUserTemporarySrpData =
            ArgumentCaptor.forClass(UserTemporarySRPData.class);
        verify(userTemporarySRPDataRepository, times(1)).delete(acUserTemporarySrpData.capture());

        UserTemporarySRPData deletedUserTemporarySrpData = acUserTemporarySrpData.getValue();
        assertEquals(serverEphemeralHex, deletedUserTemporarySrpData.getServerEphemeralHex());
        assertEquals(serverSecretHex, deletedUserTemporarySrpData.getServerSecretHex());

        verify(srp6Server, times(1)).calculateSecret(srpClientEphemeralBigInteger);
        verify(srp6Server, times(1)).verifyClientEvidenceMessage(srpClientProofBigInteger);

        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(srp6Factory);
        verifyNoMoreInteractions(srp6Server);
        verifyNoInteractions(sessionRepository);
    }

    @Test
    @WithSessionSignatureV1
    public void elevatePasswordElevatedSessionInitV1_shouldSendElevationEmail() throws IOException {
        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);

        when(sessionRepository.findById(session.getId())).thenReturn(Optional.of(session));

        authenticationService.elevatePasswordElevatedSessionInitV1();

        verify(sessionRepository, times(1)).findById(session.getId());

        ArgumentCaptor<SessionMultiFactorElevationRequest> acSessionMultiFactorElevationRequest =
            ArgumentCaptor.forClass(SessionMultiFactorElevationRequest.class);
        verify(sessionMultiFactorElevationRequestRepository, times(1)).save(acSessionMultiFactorElevationRequest.capture());

        SessionMultiFactorElevationRequest sessionMultiFactorElevationRequest =
            acSessionMultiFactorElevationRequest.getValue();
        assertEquals(session,
            sessionMultiFactorElevationRequest.getSession());

        verify(emailSendingEngine, times(1)).sendMultiFactorAuthenticationEmail(sessionMultiFactorElevationRequest);
    }

    @Test
    @WithSessionSignatureV1
    public void elevatePasswordElevatedSessionInitV1_shouldElevateSession() throws IOException {
        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);

        SessionMultiFactorElevationRequest sessionMultiFactorElevationRequest =
            SessionMultiFactorElevationRequestHelper.create();

        session.setSessionMultiFactorElevationRequests(
            new HashSet<>(Collections.singletonList(sessionMultiFactorElevationRequest))
        );

        when(sessionRepository.findById(session.getId()))
            .thenReturn(Optional.of(session));

        ElevatePasswordElevatedSessionCompleteV1Request request = new ElevatePasswordElevatedSessionCompleteV1Request();
        request.setRequestCode(sessionMultiFactorElevationRequest.getRequestCode());

        authenticationService.elevatePasswordElevatedSessionCompleteV1(request);

        verify(sessionRepository, times(1)).findById(session.getId());

        ArgumentCaptor<Session> acSession =
            ArgumentCaptor.forClass(Session.class);
        verify(sessionRepository, times(1)).save(acSession.capture());
        verifyNoMoreInteractions(sessionRepository);

        Session savedSession = acSession.getValue();
        assertEquals(SessionAssuranceLevel.MultiFactorElevatedSession, savedSession.getAssuranceLevel());
        assertEquals(0, savedSession.getSessionMultiFactorElevationRequests().size());
    }

    @Test
    @WithSessionSignatureV1
    public void elevatePasswordElevatedSessionInitV1_shouldNotElevateAuthenticationSessionWithInvalidCode() {
        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);

        SessionMultiFactorElevationRequest sessionMultiFactorElevationRequest =
            SessionMultiFactorElevationRequestHelper.create();

        session.setSessionMultiFactorElevationRequests(
            new HashSet<>(Collections.singletonList(sessionMultiFactorElevationRequest))
        );

        when(sessionRepository.findById(session.getId()))
            .thenReturn(Optional.of(session));

        ElevatePasswordElevatedSessionCompleteV1Request request = new ElevatePasswordElevatedSessionCompleteV1Request();
        request.setRequestCode("invalidCode");

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.elevatePasswordElevatedSessionCompleteV1(request), "Authentication code not " +
                "found.");

        verify(sessionRepository, times(1)).findById(session.getId());
        verifyNoMoreInteractions(sessionRepository);
    }

    @Test
    public void validateEmailAddressV1_shouldValidateEmailAddress() {
        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);
        userIdentity.setEmailValidationKey("emailValidationKey");

        ValidateEmailAddressV1Request request = new ValidateEmailAddressV1Request();
        request.setEmailValidationKey(userIdentity.getEmailValidationKey());

        when(userIdentityRepository.findByEmailValidationKey(userIdentity.getEmailValidationKey()))
            .thenReturn(Optional.of(userIdentity));

        authenticationService.validateEmailAddressV1(request);

        verify(userIdentityRepository, times(1)).findByEmailValidationKey(userIdentity.getEmailValidationKey());

        ArgumentCaptor<UserIdentity> acUserIdentity = ArgumentCaptor.forClass(UserIdentity.class);
        verify(userIdentityRepository, times(1)).save(acUserIdentity.capture());
        verifyNoMoreInteractions(userIdentityRepository);

        UserIdentity savedUserIdentity = acUserIdentity.getValue();
        assertTrue(savedUserIdentity.isEmailValidated());
    }

    @Test
    public void validateEmailAddressV1_shouldNotThrowOnInvalidEmailValidationKeysValidateEmailAddress() {
        String nonExistingEmailValidationKey = "nonExistingEmailValidationKey";

        ValidateEmailAddressV1Request request = new ValidateEmailAddressV1Request();
        request.setEmailValidationKey(nonExistingEmailValidationKey);

        when(userIdentityRepository.findByEmailValidationKey(nonExistingEmailValidationKey))
            .thenReturn(Optional.empty());

        assertDoesNotThrow(() -> authenticationService.validateEmailAddressV1(request));

        verify(userIdentityRepository, times(1)).findByEmailValidationKey(nonExistingEmailValidationKey);
        verifyNoMoreInteractions(userIdentityRepository);
    }

    @Test
    public void requestPasswordResetV1_shouldSendPasswordResetEmail() throws IOException {
        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);
        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, "cafe", "deadbeef",
            PasswordStretchingAlgorithm.Scrypt_v1);
        userAuthentication.setId(RandomUtils.alphanumericString(32));
        userIdentity.setAuthentications(Set.of(userAuthentication));

        when(userIdentityRepository.findByEmailAddress(userIdentity.getEmailAddress())).thenReturn(Optional.of(userIdentity));

        RequestPasswordResetV1Request request = new RequestPasswordResetV1Request();
        request.setEmailAddress(userIdentity.getEmailAddress());

        authenticationService.requestPasswordResetV1(request);

        ArgumentCaptor<UserAuthenticationResetRequest> acUserAuthenticationResetRequest =
            ArgumentCaptor.forClass(UserAuthenticationResetRequest.class);

        verify(userIdentityRepository, times(1)).findByEmailAddress(userIdentity.getEmailAddress());
        verify(userAuthenticationResetRequestRepository, times(1)).save(acUserAuthenticationResetRequest.capture());
        verify(emailSendingEngine, times(1)).sendPasswordResetEmail(acUserAuthenticationResetRequest.capture());
        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoMoreInteractions(userAuthenticationResetRequestRepository);
        verifyNoMoreInteractions(emailSendingEngine);

        List<UserAuthenticationResetRequest> capturedUserAuthenticationResetRequests =
            acUserAuthenticationResetRequest.getAllValues();

        UserAuthenticationResetRequest savedUserAuthenticationResetRequest =
            capturedUserAuthenticationResetRequests.get(0);
        UserAuthenticationResetRequest emailedUserAuthenticationResetRequest =
            capturedUserAuthenticationResetRequests.get(1);

        assertEquals(userAuthentication, savedUserAuthenticationResetRequest.getUserAuthentication());
        assertEquals(userAuthentication, emailedUserAuthenticationResetRequest.getUserAuthentication());
    }

    @Test
    public void requestPasswordResetV1_shouldNotThrowOnNotFoundEmailAddress() throws IOException {
        when(userIdentityRepository.findByEmailAddress(DummyData.USER_EMAIL)).thenReturn(Optional.empty());

        RequestPasswordResetV1Request request = new RequestPasswordResetV1Request();
        request.setEmailAddress(DummyData.USER_EMAIL);

        authenticationService.requestPasswordResetV1(request);

        verify(userIdentityRepository, times(1)).findByEmailAddress(DummyData.USER_EMAIL);
        verifyNoMoreInteractions(userIdentityRepository);
        verifyNoInteractions(userAuthenticationResetRequestRepository);
        verifyNoInteractions(emailSendingEngine);
    }

    @Test
    public void resetPasswordV1_shouldResetPassword() {
        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, "cafe", "deadbeef",
            PasswordStretchingAlgorithm.Scrypt_v1);
        userAuthentication.setUserIdentity(userIdentity);
        userIdentity.getAuthentications().add(userAuthentication);

        UserAuthenticationResetRequest userAuthenticationResetRequest = UserAuthenticationResetRequestHelper.create();
        userAuthenticationResetRequest.setUserAuthentication(userAuthentication);

        when(userAuthenticationResetRequestRepository.findByRequestKey(userAuthenticationResetRequest.getRequestKey()
            , 3))
            .thenReturn(Optional.of(userAuthenticationResetRequest));

        ResetPasswordV1Request request = new ResetPasswordV1Request();
        request.setPasswordResetKey(userAuthenticationResetRequest.getRequestKey());

        String newSalt = "efac";
        request.setSrpSaltHex(newSalt);

        String newVerifier = "feebdaed";
        request.setSrpVerifierHex(newVerifier);

        PasswordStretchingAlgorithm newPasswordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;
        request.setPasswordStretchingAlgorithm(newPasswordStretchingAlgorithm);

        authenticationService.resetPasswordV1(request);

        verify(userAuthenticationResetRequestRepository, times(1))
            .findByRequestKey(userAuthenticationResetRequest.getRequestKey(), 3);

        ArgumentCaptor<UserIdentity> acUserIdentity = ArgumentCaptor.forClass(UserIdentity.class);
        verify(userIdentityRepository, times(1)).save(acUserIdentity.capture());

        UserIdentity savedUserIdentity = acUserIdentity.getValue();
        assertEquals(2, savedUserIdentity.getAuthentications().size());

        UserAuthentication currentAuthentication = UserIdentityHelper.getCurrentAuthentication(userIdentity);
        assertEquals(newSalt, currentAuthentication.getSrpSaltHex());
        assertEquals(newVerifier, currentAuthentication.getSrpVerifierHex());
        assertEquals(newPasswordStretchingAlgorithm, currentAuthentication.getPasswordStretchingAlgorithm());

        ArgumentCaptor<UserAuthenticationResetRequest> acUserAuthenticationResetRequest =
            ArgumentCaptor.forClass(UserAuthenticationResetRequest.class);
        verify(userAuthenticationResetRequestRepository, times(1)).delete(acUserAuthenticationResetRequest.capture());
        UserAuthenticationResetRequest deletedUserAuthenticationResetRequest =
            acUserAuthenticationResetRequest.getValue();

        assertEquals(userAuthenticationResetRequest.getRequestKey(),
            deletedUserAuthenticationResetRequest.getRequestKey());

        verifyNoMoreInteractions(userAuthenticationResetRequestRepository);
        verifyNoMoreInteractions(userIdentityRepository);
    }

    @Test
    public void resetPasswordV1_shouldNotResetPasswordIfRequestExpired() {
        UserAuthenticationResetRequest userAuthenticationResetRequest = UserAuthenticationResetRequestHelper.create();
        userAuthenticationResetRequest.setExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));

        when(userAuthenticationResetRequestRepository.findByRequestKey(userAuthenticationResetRequest.getRequestKey()
            , 3))
            .thenReturn(Optional.of(userAuthenticationResetRequest));

        ResetPasswordV1Request request = new ResetPasswordV1Request();
        request.setPasswordResetKey(userAuthenticationResetRequest.getRequestKey());

        String newSalt = "efac";
        request.setSrpSaltHex(newSalt);

        String newVerifier = "feebdaed";
        request.setSrpVerifierHex(newVerifier);

        PasswordStretchingAlgorithm newPasswordStretchingAlgorithm = PasswordStretchingAlgorithm.Scrypt_v1;
        request.setPasswordStretchingAlgorithm(newPasswordStretchingAlgorithm);

        assertThrows(UnauthorizedException.class, () -> authenticationService.resetPasswordV1(request), "Password " +
            "reset request expired.");

        verify(userAuthenticationResetRequestRepository, times(1))
            .findByRequestKey(userAuthenticationResetRequest.getRequestKey(), 3);

        verifyNoMoreInteractions(userAuthenticationResetRequestRepository);
        verifyNoMoreInteractions(userIdentityRepository);
    }

    @Test
    public void resetPasswordV1_shouldNotResetPasswordIfInvalidKeyButShouldNotThrow() {
        String invalidRequestKey = "invalidRequestKey";
        when(userAuthenticationResetRequestRepository.findByRequestKey(invalidRequestKey, 3))
            .thenReturn(Optional.empty());

        ResetPasswordV1Request request = new ResetPasswordV1Request();
        request.setPasswordResetKey(invalidRequestKey);
        request.setSrpSaltHex("cafe");
        request.setSrpVerifierHex("deadbeef");
        request.setPasswordStretchingAlgorithm(PasswordStretchingAlgorithm.Scrypt_v1);

        authenticationService.resetPasswordV1(request);

        verify(userAuthenticationResetRequestRepository, times(1)).findByRequestKey(invalidRequestKey, 3);

        verifyNoInteractions(userIdentityRepository);
        verifyNoMoreInteractions(userAuthenticationResetRequestRepository);
    }

    @Test
    @WithAuthenticationSessionSignatureV1
    public void getCurrentUserIdentity_withAuthenticationSession_shouldReturnUserIdentity() {
        UserIdentity currentUserIdentity = authenticationService.getCurrentUserIdentity();
        assertEquals(DummyData.USER_EMAIL, currentUserIdentity.getEmailAddress());
        assertEquals(DummyData.USER_FIRST_NAME, currentUserIdentity.getFirstName());
        assertEquals(DummyData.USER_LAST_NAME, currentUserIdentity.getLastName());
    }

    @Test
    @WithDeviceSignatureV1
    public void getCurrentUserIdentity_withDevice_shouldReturnUserIdentity() {
        UserIdentity currentUserIdentity = authenticationService.getCurrentUserIdentity();
        assertEquals(DummyData.USER_EMAIL, currentUserIdentity.getEmailAddress());
        assertEquals(DummyData.USER_FIRST_NAME, currentUserIdentity.getFirstName());
        assertEquals(DummyData.USER_LAST_NAME, currentUserIdentity.getLastName());
    }

    @Test
    @WithSessionSignatureV1
    public void getCurrentUserIdentity_withSession_shouldReturnUserIdentity() {
        UserIdentity currentUserIdentity = authenticationService.getCurrentUserIdentity();
        assertEquals(DummyData.USER_EMAIL, currentUserIdentity.getEmailAddress());
        assertEquals(DummyData.USER_FIRST_NAME, currentUserIdentity.getFirstName());
        assertEquals(DummyData.USER_LAST_NAME, currentUserIdentity.getLastName());
    }

    @Test
    public void getCurrentUserIdentity_withoutLogin_shouldThrow() {
        assertThrows(IllegalStateException.class, () -> authenticationService.getCurrentUserIdentity(), "There is no " +
            "authentication in the SecurityContext.");
    }

    @Test
    @WithAuthenticationSessionSignatureV1
    public void getCurrentAuthenticationDetails_withAuthenticationSession_shouldReturnAuthenticationDetails() {
        AuthenticationDetails authenticationDetails = authenticationService.getCurrentAuthenticationDetails();
        assertEquals(DiplomatiqAuthenticationScheme.AuthenticationSessionSignatureV1,
            authenticationDetails.getDiplomatiqAuthenticationScheme());
        assertEquals(DummyData.AUTHENTICATION_SESSION_ID, authenticationDetails.getAuthenticationId());
    }

    @Test
    @WithDeviceSignatureV1
    public void getCurrentAuthenticationDetails_withDevice_shouldReturnAuthenticationDetails() {
        AuthenticationDetails authenticationDetails = authenticationService.getCurrentAuthenticationDetails();
        assertEquals(DiplomatiqAuthenticationScheme.DeviceSignatureV1,
            authenticationDetails.getDiplomatiqAuthenticationScheme());
        assertEquals(DummyData.DEVICE_ID, authenticationDetails.getAuthenticationId());
    }

    @Test
    @WithSessionSignatureV1
    public void getCurrentAuthenticationDetails_withSession_shouldReturnAuthenticationDetails() {
        AuthenticationDetails authenticationDetails = authenticationService.getCurrentAuthenticationDetails();
        assertEquals(DiplomatiqAuthenticationScheme.SessionSignatureV1,
            authenticationDetails.getDiplomatiqAuthenticationScheme());
        assertEquals(DummyData.SESSION_ID, authenticationDetails.getAuthenticationId());
    }

    @Test
    public void getCurrentAuthenticationDetails_withoutLogin_shouldThrow() {
        assertThrows(IllegalStateException.class, () -> authenticationService.getCurrentAuthenticationDetails(),
            "There is no " +
                "authentication in the SecurityContext.");
    }

    @Test
    public void getDeviceKeyByDeviceId_shouldReturnDeviceKey() {
        UserDevice userDevice = UserDeviceHelper.create();
        userDevice.setId(DummyData.DEVICE_ID);

        when(userDeviceRepository.findById(userDevice.getId())).thenReturn(Optional.of(userDevice));

        byte[] deviceKey = authenticationService.getDeviceKeyByDeviceId(userDevice.getId());

        verify(userDeviceRepository, times(1)).findById(userDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);

        assertArrayEquals(userDevice.getDeviceKey(), deviceKey);
    }

    @Test
    public void getAuthenticationSessionByAuthenticationSessionId_shouldReturnAuthenticationSessionKey() {
        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(RandomUtils.bytes(32));
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);

        when(authenticationSessionRepository.findById(authenticationSession.getId()))
            .thenReturn(Optional.of(authenticationSession));

        byte[] authenticationSessionKey =
            authenticationService.getAuthenticationSessionKeyByAuthenticationSessionId(authenticationSession.getId());

        verify(authenticationSessionRepository, times(1)).findById(authenticationSession.getId());
        verifyNoMoreInteractions(authenticationSessionRepository);

        assertArrayEquals(authenticationSession.getAuthenticationSessionKey(), authenticationSessionKey);
    }

    @Test
    public void verifyAuthenticationSessionCredentials_shouldReturnUserIdentity() {
        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        UserAuthentication userAuthentication = UserAuthenticationHelper.create(userIdentity, "cafe", "deadbeef",
            PasswordStretchingAlgorithm.Scrypt_v1);
        userAuthentication.setUserIdentity(userIdentity);

        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(RandomUtils.bytes(32));
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);
        authenticationSession.setUserAuthentication(userAuthentication);

        when(authenticationSessionRepository.findById(authenticationSession.getId(), 2)).thenReturn(Optional.of(authenticationSession));

        UserIdentity returnedUserIdentity =
            authenticationService.verifyAuthenticationSessionCredentials(authenticationSession.getId());

        verify(authenticationSessionRepository, times(1)).findById(authenticationSession.getId(), 2);
        verifyNoMoreInteractions(authenticationSessionRepository);

        assertEquals(userIdentity.getEmailAddress(), returnedUserIdentity.getEmailAddress());
    }

    @Test
    public void verifyAuthenticationSessionCredentials_shouldThrowIfExpired() {
        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(RandomUtils.bytes(32));
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);
        authenticationSession.setExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));

        when(authenticationSessionRepository.findById(authenticationSession.getId(), 2)).thenReturn(Optional.of(authenticationSession));

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.verifyAuthenticationSessionCredentials(authenticationSession.getId()),
            "Authentication session expired.");

        verify(authenticationSessionRepository, times(1)).findById(authenticationSession.getId(), 2);
        verifyNoMoreInteractions(authenticationSessionRepository);
    }

    @Test
    public void verifyDeviceCredentials_shouldReturnUserIdentity() {
        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        UserDevice userDevice = UserDeviceHelper.create();
        userDevice.setId(DummyData.DEVICE_ID);
        userDevice.setUserIdentity(userIdentity);

        when(userDeviceRepository.findById(userDevice.getId())).thenReturn(Optional.of(userDevice));

        UserIdentity returnedUserIdentity = authenticationService.verifyDeviceCredentials(userDevice.getId());

        verify(userDeviceRepository, times(1)).findById(userDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);

        assertEquals(userIdentity.getEmailAddress(), returnedUserIdentity.getEmailAddress());
    }

    @Test
    public void verifySessionCredentials_shouldReturnUserIdentity() {
        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        UserDevice userDevice = UserDeviceHelper.create();
        userDevice.setId(DummyData.DEVICE_ID);
        userDevice.setUserIdentity(userIdentity);

        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);
        session.setUserDevice(userDevice);
        userDevice.setSession(session);

        when(userDeviceRepository.findById(userDevice.getId())).thenReturn(Optional.of(userDevice));

        UserIdentity returnedUserIdentity = authenticationService.verifySessionCredentials(userDevice.getId(),
            session.getId());

        verify(userDeviceRepository, times(1)).findById(userDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);

        assertEquals(userIdentity.getEmailAddress(), returnedUserIdentity.getEmailAddress());
    }

    @Test
    public void verifySessionCredentials_shouldThrowIfSessionAndDeviceAreUnrelated() {
        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        UserDevice userDevice = UserDeviceHelper.create();
        userDevice.setId(DummyData.DEVICE_ID);
        userDevice.setUserIdentity(userIdentity);

        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);
        session.setUserDevice(userDevice);
        userDevice.setSession(session);

        String anotherSessionId = "anotherSessionId";

        when(userDeviceRepository.findById(userDevice.getId())).thenReturn(Optional.of(userDevice));

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.verifySessionCredentials(userDevice.getId(),
                anotherSessionId), "Device and session are unrelated.");

        verify(userDeviceRepository, times(1)).findById(userDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);
    }

    @Test
    public void verifySessionCredentials_shouldThrowIfExpired() {
        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL, DummyData.USER_FIRST_NAME,
            DummyData.USER_LAST_NAME);

        UserDevice userDevice = UserDeviceHelper.create();
        userDevice.setId(DummyData.DEVICE_ID);
        userDevice.setUserIdentity(userIdentity);

        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);
        session.setUserDevice(userDevice);
        userDevice.setSession(session);
        session.setExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));

        when(userDeviceRepository.findById(userDevice.getId())).thenReturn(Optional.of(userDevice));

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.verifySessionCredentials(userDevice.getId(), session.getId()), "Session " +
                "expired.");

        verify(userDeviceRepository, times(1)).findById(userDevice.getId());
        verifyNoMoreInteractions(userDeviceRepository);
    }

    @Test
    public void sessionHasAssuranceLevel_shouldReturnValidValues() {
        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);

        when(sessionRepository.findById(session.getId())).thenReturn(Optional.of(session));

        assertTrue(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.RegularSession));
        assertFalse(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.PasswordElevatedSession));
        assertFalse(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.MultiFactorElevatedSession));
        verify(sessionRepository, times(3)).findById(session.getId());

        SessionHelper.elevateSessionToPasswordElevated(session);
        assertTrue(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.RegularSession));
        assertTrue(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.PasswordElevatedSession));
        assertFalse(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.MultiFactorElevatedSession));
        verify(sessionRepository, times(6)).findById(session.getId());

        SessionHelper.elevateSessionToMultiFactorElevated(session);
        assertTrue(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.RegularSession));
        assertTrue(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.PasswordElevatedSession));
        assertTrue(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.MultiFactorElevatedSession));
        verify(sessionRepository, times(9)).findById(session.getId());

        verifyNoMoreInteractions(sessionRepository);
    }

    @Test
    public void sessionHasAssuranceLevel_shouldThrowUnauthorizedIfNotFound() {
        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);

        when(sessionRepository.findById(session.getId())).thenReturn(Optional.empty());

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.sessionHasAssuranceLevel(session.getId(),
                SessionAssuranceLevel.RegularSession), "No session found with the given ID.");

        verify(sessionRepository, times(1)).findById(session.getId());
        verifyNoMoreInteractions(sessionRepository);
    }

    @Test
    public void sessionHasAssuranceLevel_shouldDowngradeToRegularIfAssuranceLevelExpired() {
        Session session = SessionHelper.create();
        session.setId(DummyData.SESSION_ID);

        when(sessionRepository.findById(session.getId())).thenReturn(Optional.of(session));

        SessionHelper.elevateSessionToPasswordElevated(session);
        session.setAssuranceLevelExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));
        assertTrue(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.RegularSession));
        assertEquals(session.getExpirationTime(), session.getAssuranceLevelExpirationTime());
        verify(sessionRepository, times(1)).findById(session.getId());
        verify(sessionRepository, times(1)).save(session);

        SessionHelper.elevateSessionToPasswordElevated(session);
        session.setAssuranceLevelExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));
        assertFalse(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.PasswordElevatedSession));
        assertEquals(session.getExpirationTime(), session.getAssuranceLevelExpirationTime());
        verify(sessionRepository, times(2)).findById(session.getId());
        verify(sessionRepository, times(2)).save(session);

        SessionHelper.elevateSessionToPasswordElevated(session);
        session.setAssuranceLevelExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));
        assertFalse(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.MultiFactorElevatedSession));
        assertEquals(session.getExpirationTime(), session.getAssuranceLevelExpirationTime());
        verify(sessionRepository, times(3)).findById(session.getId());
        verify(sessionRepository, times(3)).save(session);

        SessionHelper.elevateSessionToMultiFactorElevated(session);
        session.setAssuranceLevelExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));
        assertTrue(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.RegularSession));
        assertEquals(session.getExpirationTime(), session.getAssuranceLevelExpirationTime());
        verify(sessionRepository, times(4)).findById(session.getId());
        verify(sessionRepository, times(4)).save(session);

        SessionHelper.elevateSessionToMultiFactorElevated(session);
        session.setAssuranceLevelExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));
        assertFalse(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.PasswordElevatedSession));
        assertEquals(session.getExpirationTime(), session.getAssuranceLevelExpirationTime());
        verify(sessionRepository, times(5)).findById(session.getId());
        verify(sessionRepository, times(5)).save(session);

        SessionHelper.elevateSessionToMultiFactorElevated(session);
        session.setAssuranceLevelExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));
        assertFalse(authenticationService.sessionHasAssuranceLevel(session.getId(),
            SessionAssuranceLevel.MultiFactorElevatedSession));
        assertEquals(session.getExpirationTime(), session.getAssuranceLevelExpirationTime());
        verify(sessionRepository, times(6)).findById(session.getId());
        verify(sessionRepository, times(6)).save(session);

        verifyNoMoreInteractions(sessionRepository);
    }

    @Test
    public void authenticationSessionHasAssuranceLevel_shouldReturnValidValues() {
        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(RandomUtils.bytes(32));
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);

        when(authenticationSessionRepository.findById(authenticationSession.getId()))
            .thenReturn(Optional.of(authenticationSession));

        assertTrue(authenticationService.authenticationSessionHasAssuranceLevel(authenticationSession.getId(),
            SessionAssuranceLevel.PasswordElevatedSession));
        assertFalse(authenticationService.authenticationSessionHasAssuranceLevel(authenticationSession.getId(),
            SessionAssuranceLevel.MultiFactorElevatedSession));

        AuthenticationSessionHelper.elevateAuthenticationSessionToMultiFactorElevated(authenticationSession);
        assertTrue(authenticationService.authenticationSessionHasAssuranceLevel(authenticationSession.getId(),
            SessionAssuranceLevel.PasswordElevatedSession));
        assertTrue(authenticationService.authenticationSessionHasAssuranceLevel(authenticationSession.getId(),
            SessionAssuranceLevel.MultiFactorElevatedSession));

        verify(authenticationSessionRepository, times(4)).findById(authenticationSession.getId());
        verifyNoMoreInteractions(authenticationSessionRepository);
    }

    @Test
    public void authenticationSessionHasAssuranceLevel_shouldThrowUnauthorizedIfNotFound() {
        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(RandomUtils.bytes(32));
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);

        when(authenticationSessionRepository.findById(authenticationSession.getId()))
            .thenReturn(Optional.empty());

        assertThrows(UnauthorizedException.class,
            () -> authenticationService.authenticationSessionHasAssuranceLevel(authenticationSession.getId(),
                SessionAssuranceLevel.RegularSession), "No authentication session found with the given ID.");

        verify(authenticationSessionRepository, times(1)).findById(authenticationSession.getId());
        verifyNoMoreInteractions(authenticationSessionRepository);
    }

    @Test
    public void authenticationSessionHasAssuranceLevel_shouldDowngradeToRegularIfAssuranceLevelExpired() {
        AuthenticationSession authenticationSession = AuthenticationSessionHelper.create(RandomUtils.bytes(32));
        authenticationSession.setId(DummyData.AUTHENTICATION_SESSION_ID);

        when(authenticationSessionRepository.findById(authenticationSession.getId()))
            .thenReturn(Optional.of(authenticationSession));

        AuthenticationSessionHelper.elevateAuthenticationSessionToMultiFactorElevated(authenticationSession);
        authenticationSession.setAssuranceLevelExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));
        assertTrue(authenticationService.authenticationSessionHasAssuranceLevel(authenticationSession.getId(),
            SessionAssuranceLevel.PasswordElevatedSession));
        assertEquals(authenticationSession.getExpirationTime(), authenticationSession.getAssuranceLevelExpirationTime());

        AuthenticationSessionHelper.elevateAuthenticationSessionToMultiFactorElevated(authenticationSession);
        authenticationSession.setAssuranceLevelExpirationTime(Instant.now().minus(Duration.ofMinutes(5)));
        assertFalse(authenticationService.authenticationSessionHasAssuranceLevel(authenticationSession.getId(),
            SessionAssuranceLevel.MultiFactorElevatedSession));
        assertEquals(authenticationSession.getExpirationTime(), authenticationSession.getAssuranceLevelExpirationTime());
    }
}
