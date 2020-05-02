package org.diplomatiq.diplomatiqbackend.utils.crypto.srp;

import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Component
public class SRP6Factory {
    private static final SRP6GroupParameters SRP6_GROUP_PARAMETERS = SRP6StandardGroups.rfc5054_8192;
    private static final GeneralDigest SRP6_DIGEST = new SHA256Digest();
    private static final SecureRandom SECURE_RANDOM = getSecureRandom();

    private static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            return new SecureRandom();
        }
    }

    public RequestBoundaryCrossingSRP6Server getSrp6Server(BigInteger verifier) {
        RequestBoundaryCrossingSRP6Server srp6Server = new RequestBoundaryCrossingSRP6Server();
        srp6Server.init(SRP6_GROUP_PARAMETERS, verifier, SRP6_DIGEST, SECURE_RANDOM);
        return srp6Server;
    }

    public SRP6Client getSrp6Client() {
        SRP6Client srp6Client = new SRP6Client();
        srp6Client.init(SRP6_GROUP_PARAMETERS, SRP6_DIGEST, SECURE_RANDOM);
        return srp6Client;
    }

    public SRP6VerifierGenerator getSrp6VerifierGenerator() {
        SRP6VerifierGenerator srp6VerifierGenerator = new SRP6VerifierGenerator();
        srp6VerifierGenerator.init(SRP6_GROUP_PARAMETERS, SRP6_DIGEST);
        return srp6VerifierGenerator;
    }
}
