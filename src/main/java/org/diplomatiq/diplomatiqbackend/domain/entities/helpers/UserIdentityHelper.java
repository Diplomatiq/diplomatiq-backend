package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.*;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.AbstractPasswordStretchingAlgorithmImpl;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingEngine;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.DeviceContainerKeyGenerator;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.DeviceKeyGenerator;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Set;

@Component
public class UserIdentityHelper {
    @Autowired
    PasswordStretchingEngine passwordStretchingEngine;

    public UserIdentity createUserIdentity(String emailAddress, String firstName,
                                           String lastName) throws NoSuchAlgorithmException {
        String lowercaseEmailAddress = emailAddress.toLowerCase();
        byte[] lowercaseEmailAddressBytes = lowercaseEmailAddress.getBytes(StandardCharsets.UTF_8);
        byte[] lowercaseEmailAddressDigest = MessageDigest.getInstance("SHA-256").digest(lowercaseEmailAddressBytes);
        String lowercaseEmailAddressDigestBase64 = Base64.getEncoder().encodeToString(lowercaseEmailAddressDigest);

        UserIdentity userIdentity = new UserIdentity();

        userIdentity.setEmailAddress(lowercaseEmailAddress);
        userIdentity.setEmailAddressDigestBase64(lowercaseEmailAddressDigestBase64);
        userIdentity.setFirstName(firstName);
        userIdentity.setLastName(lastName);
        userIdentity.setValidated(false);

        return userIdentity;
    }

    public UserIdentity dummyUserIdentity(byte[] serverEphemeralBytes) {
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
        device.setDeviceKey(DeviceKeyGenerator.generate());
        userIdentity.setDevices(Set.of(device));

        UserDeviceContainer deviceContainer = new UserDeviceContainer();
        deviceContainer.setDeviceContainerKey(DeviceContainerKeyGenerator.generate());
        device.setUserDeviceContainers(Set.of(deviceContainer));

        return userIdentity;
    }
}
