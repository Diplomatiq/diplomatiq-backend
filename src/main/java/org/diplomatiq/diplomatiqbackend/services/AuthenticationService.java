package org.diplomatiq.diplomatiqbackend.services;

import org.diplomatiq.diplomatiqbackend.methods.entities.UserIdentity;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

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

    public UserIdentity getUserBySessionId(String sessionId) {
        if (sessionId == null) {
            throw new IllegalArgumentException("sessionId must not be null");
        }

        if (sessionId.equals("")) {
            throw new IllegalArgumentException("sessionId must not be empty");
        }

        return new UserIdentity("asd", "soma.lucz@diplomatiq.org");
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

}
