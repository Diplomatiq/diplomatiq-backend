package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingEngine;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UserIdentityHelper {
    @Autowired
    PasswordStretchingEngine passwordStretchingEngine;

    @Autowired
    UserAuthenticationHelper userAuthenticationHelper;

    @Autowired
    UserDeviceHelper userDeviceHelper;

    public UserIdentity createUserIdentity(String emailAddress, String firstName, String lastName) {
        UserIdentity userIdentity = new UserIdentity();

        userIdentity.setEmailAddress(emailAddress.toLowerCase());
        userIdentity.setFirstName(firstName);
        userIdentity.setLastName(lastName);
        userIdentity.setValidated(false);

        return userIdentity;
    }

    public UserIdentity dummyUserIdentity(byte[] serverEphemeralBytes) {
//        final String emailAddress = "samsepi0l@diplomatiq.org";
//
//        PasswordStretchingAlgorithm passwordStretchingAlgorithm = passwordStretchingEngine.getLatestAlgorithm();
//        AbstractPasswordStretchingAlgorithmImpl passwordStretchingAlgorithmImpl =
//            passwordStretchingEngine.getImplByAlgorithm(passwordStretchingAlgorithm);
//
//        byte[] srpSalt = RandomUtils.strongBytes(32);
//
//        SRP6VerifierGenerator srp6VerifierGenerator = new SRP6VerifierGenerator();
//        srp6VerifierGenerator.init(SRP6StandardGroups.rfc5054_8192, passwordStretchingAlgorithmImpl);
//
//        byte[] emailAddressBytes = emailAddress.getBytes(StandardCharsets.UTF_8);
//
//        String password = RandomUtils.alphanumericString(32);
//        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
//
//        BigInteger srpVerifierBigInteger = srp6VerifierGenerator.generateVerifier(srpSalt, emailAddressBytes,
//            passwordBytes);
//        byte[] srpVerifierBytes = srpVerifierBigInteger.toByteArray();
//
//        BigInteger serverEphemeralBigInt = serverEphemeralBytes != null
//            ? new BigInteger(serverEphemeralBytes)
//            : new BigInteger("5");

        UserIdentity userIdentity = createUserIdentity("samsepi0l@diplomatiq.org", "Sam", "Sepiol");
//
//        UserTemporarySRPLoginData userTemporarySRPLoginData = new UserTemporarySRPLoginData();
//        userTemporarySRPLoginData.setServerEphemeral(serverEphemeralBigInt.toByteArray());
//
//        UserAuthentication userAuthentication =
//            userAuthenticationHelper.createUserAuthenticationForRegistration(srpSalt, srpVerifierBytes,
//                passwordStretchingAlgorithm);
//
//        userAuthentication.setUserTemporarySrpLoginDatas(Set.of(userTemporarySRPLoginData));
//        userIdentity.setAuthentications(Set.of(userAuthentication));
//
//        UserDevice device = userDeviceHelper.dummyUserDevice();
//        device.setDeviceKey(DeviceKeyGenerator.generate());
//        device.setDeviceContainerKey(DeviceContainerKeyGenerator.generate());
//        device.setSessionToken();
//        userIdentity.setDevices(Set.of(device));

        return userIdentity;
    }
}
