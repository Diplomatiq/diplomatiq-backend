package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class LoginV1Request {
    @Schema(
        description = "The ID of an authentication session",
        example = "ctH0k28okpk1NTyDANzCDoTnLuzlvzj1"
    )
    @NotBlank
    private String authenticationSessionId;

    public String getAuthenticationSessionId() {
        return authenticationSessionId;
    }

    public void setAuthenticationSessionId(String authenticationSessionId) {
        this.authenticationSessionId = authenticationSessionId;
    }
}
