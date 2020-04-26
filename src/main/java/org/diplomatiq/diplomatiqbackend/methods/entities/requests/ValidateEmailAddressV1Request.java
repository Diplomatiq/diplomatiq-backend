package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class ValidateEmailAddressV1Request {
    @Schema(
        description = "The email validation key the user received in email",
        example =
            "9i6ExDuo9dpvvV8djypUhQNlomvODXO0S5lRCFvxNHyiiiZTm3iT87Doj5IFDwhlSHpbiEKRPEcK0Fb4OdPRTYVmOd39gJIxE4AgI3hw6ZUcrDcz05i1jjrMEQydL819tbU6y02XgNOl4evk2oYGK1"
    )
    @NotBlank
    private String emailValidationKey;

    public String getEmailValidationKey() {
        return emailValidationKey;
    }

    public void setEmailValidationKey(String emailValidationKey) {
        this.emailValidationKey = emailValidationKey;
    }
}
