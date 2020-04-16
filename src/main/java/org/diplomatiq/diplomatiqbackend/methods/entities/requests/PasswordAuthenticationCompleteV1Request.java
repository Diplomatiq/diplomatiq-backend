package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

public class PasswordAuthenticationCompleteV1Request {
    @NotBlank
    @Email
    private String emailAddressDigestBase64;

    @NotBlank
    private String clientEphemeralBase64;

    @NotBlank
    private String clientProofBase64;

    @NotBlank
    private String serverEphemeralBase64;

    public String getEmailAddressDigestBase64() {
        return emailAddressDigestBase64;
    }

    public void setEmailAddressDigestBase64(String emailAddressDigestBase64) {
        this.emailAddressDigestBase64 = emailAddressDigestBase64;
    }

    public String getClientEphemeralBase64() {
        return clientEphemeralBase64;
    }

    public void setClientEphemeralBase64(String clientEphemeralBase64) {
        this.clientEphemeralBase64 = clientEphemeralBase64;
    }

    public String getClientProofBase64() {
        return clientProofBase64;
    }

    public void setClientProofBase64(String clientProofBase64) {
        this.clientProofBase64 = clientProofBase64;
    }

    public String getServerEphemeralBase64() {
        return serverEphemeralBase64;
    }

    public void setServerEphemeralBase64(String serverEphemeralBase64) {
        this.serverEphemeralBase64 = serverEphemeralBase64;
    }
}
