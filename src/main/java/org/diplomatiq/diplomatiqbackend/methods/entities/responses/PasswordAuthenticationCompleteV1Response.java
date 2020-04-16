package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import javax.validation.constraints.NotBlank;

public class PasswordAuthenticationCompleteV1Response {
    @NotBlank
    private String serverProofBase64;

    @NotBlank
    private String encryptedAuthenticationSessionIdBase64;

    public PasswordAuthenticationCompleteV1Response(@NotBlank String serverProofBase64,
                                                    @NotBlank String encryptedAuthenticationSessionIdBase64) {
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
