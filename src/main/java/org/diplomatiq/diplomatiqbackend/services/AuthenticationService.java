package org.diplomatiq.diplomatiqbackend.services;

import org.diplomatiq.diplomatiqbackend.methods.entities.UserIdentity;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    public String validateAndDecryptEncryptedSessionId(String encryptedSessionId, String deviceId) {
        String decryptedSessionId = "decryptedSessionId";

        return decryptedSessionId;
    }

    public UserIdentity lookupUserBySessionId(String sessionId) {
        return new UserIdentity("asd", "soma.lucz@diplomatiq.org");
    }
}
