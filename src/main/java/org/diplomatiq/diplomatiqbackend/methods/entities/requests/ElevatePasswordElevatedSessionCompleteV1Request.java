package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class ElevatePasswordElevatedSessionCompleteV1Request {
    @Schema(
        description = "The multi-factor authentication code",
        example = "12345678"
    )
    @NotBlank
    private String requestCode;

    public String getRequestCode() {
        return requestCode;
    }

    public void setRequestCode(String requestCode) {
        this.requestCode = requestCode;
    }
}
