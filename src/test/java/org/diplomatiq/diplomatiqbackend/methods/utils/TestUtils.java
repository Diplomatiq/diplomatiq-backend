package org.diplomatiq.diplomatiqbackend.methods.utils;

import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.RegisterUserV1Request;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.diplomatiq.diplomatiqbackend.services.RegistrationService;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

@Component
public class TestUtils {
    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    public UserIdentity registerUser() throws IOException {
        return registerUser("");
    }

    public UserIdentity registerUser(String password) throws IOException {
        String emailAddress = String.format("%s@diplomatiq.org", RandomUtils.lowercaseString(10));
        String firstName = RandomUtils.alphabeticString(10);
        String lastName = RandomUtils.alphabeticString(10);

        byte[] srpSaltBytes = RandomUtils.bytes(32);
        String srpSaltHex = new BigInteger(1, srpSaltBytes).toString(16);

        byte[] identityBytes = emailAddress.getBytes(StandardCharsets.UTF_8);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

        SRP6VerifierGenerator srp6VerifierGenerator = new SRP6VerifierGenerator();
        srp6VerifierGenerator.init(SRP6StandardGroups.rfc5054_8192, new SHA256Digest());
        BigInteger srpVerifierBigInteger = srp6VerifierGenerator.generateVerifier(srpSaltBytes, identityBytes, passwordBytes);
        String srpVerifierHex = srpVerifierBigInteger.toString(16);

        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Argon2_v1;

        RegisterUserV1Request request = new RegisterUserV1Request();
        request.setEmailAddress(emailAddress);
        request.setFirstName(firstName);
        request.setLastName(lastName);
        request.setSrpSaltHex(srpSaltHex);
        request.setSrpVerifierHex(srpVerifierHex);
        request.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);

        registrationService.registerUserV1(request);

        return userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();
    }
}
