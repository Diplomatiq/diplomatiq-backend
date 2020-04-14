package org.diplomatiq.diplomatiqbackend.methods.entities;

public class PasswordAuthenticationCompleteV1Response {
    private final String serverProofBase64;
    private final String encryptedAuthenticationSessionIdBase64;

    public PasswordAuthenticationCompleteV1Response(String serverProofBase64, String encryptedAuthenticationSessionIdBase64) {
        this.serverProofBase64 = serverProofBase64;
        this.encryptedAuthenticationSessionIdBase64 = encryptedAuthenticationSessionIdBase64;
    }

    public String getServerProofBase64() {
        return serverProofBase64;
    }

    public String getEncryptedAuthenticationSessionIdBase64() {
        return encryptedAuthenticationSessionIdBase64;
    }
}
