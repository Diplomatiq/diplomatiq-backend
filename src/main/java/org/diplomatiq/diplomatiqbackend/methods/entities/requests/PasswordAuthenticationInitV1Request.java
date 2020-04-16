package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import javax.validation.constraints.NotBlank;

public class PasswordAuthenticationInitV1Request {
    @NotBlank
    private String emailAddressDigestBase64;

    public String getEmailAddressDigestBase64() {
        return emailAddressDigestBase64;
    }

    public void setEmailAddressDigestBase64(String emailAddressDigestBase64) {
        this.emailAddressDigestBase64 = emailAddressDigestBase64;
    }
}
