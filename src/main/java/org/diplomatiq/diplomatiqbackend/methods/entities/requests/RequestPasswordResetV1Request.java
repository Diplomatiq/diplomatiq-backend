package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

public class RequestPasswordResetV1Request {
    @Schema(
        description = "The email address of the user",
        example = "samsepi0l@diplomatiq.org"
    )
    @NotBlank
    @Email
    private String emailAddress;

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }
}
