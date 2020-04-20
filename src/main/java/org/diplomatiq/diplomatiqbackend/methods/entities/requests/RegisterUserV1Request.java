package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;

import javax.validation.constraints.Email;
import javax.validation.constraints.Max;
import javax.validation.constraints.NotBlank;

public class RegisterUserV1Request {
    @Schema(
        description = "The email address of the user, it will be stored as its lowercase invariant!",
        example = "samsepi0l@diplomatiq.org"
    )
    @NotBlank
    @Email
    private String emailAddress;

    @Schema(
        description = "The first name(s) of the user",
        example = "Sam"
    )
    @NotBlank
    @Max(200)
    private String firstName;

    @Schema(
        description = "The last name(s) of the user",
        example = "Sepiol"
    )
    @Max(200)
    @NotBlank
    private String lastName;

    @Schema(
        description = "The SRP salt (s) as a Base64 string",
        example = "VvyPbq9KiilnQf+rzKvW167aglv/z+YEdddcCSMEqb8="
    )
    @NotBlank
    private String srpSaltBase64;

    @Schema(
        description = "The SRP verifier (s) as a Base64 string",
        example = "pjYlRJLsD3OR1rWW7JJrkYZndQct/XWMbrxRv3J37Gypf2zwMW1/qQornoc2bPgTpT3NxqswP8yTKleD9ir/t" +
            "+AnUYnxZbi5GaIGdATm8qoFNMmaMiSmNlwTZ9zZ7wBTdtbyCiswDDB/evzt6gj7LXozQPE7W5411S8LgmcKsX4="
    )
    @NotBlank
    private String srpVerifierBase64;

    @Schema(
        description = "The hash function used for calculating the exponent of the SRP verifier (v) as a Base64 string",
        example = "Argon2_v1"
    )
    @NotBlank
    private PasswordStretchingAlgorithm passwordStretchingAlgorithm;

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getSrpSaltBase64() {
        return srpSaltBase64;
    }

    public void setSrpSaltBase64(String srpSaltBase64) {
        this.srpSaltBase64 = srpSaltBase64;
    }

    public String getSrpVerifierBase64() {
        return srpVerifierBase64;
    }

    public void setSrpVerifierBase64(String srpVerifierBase64) {
        this.srpVerifierBase64 = srpVerifierBase64;
    }

    public PasswordStretchingAlgorithm getPasswordStretchingAlgorithm() {
        return passwordStretchingAlgorithm;
    }

    public void setPasswordStretchingAlgorithm(PasswordStretchingAlgorithm passwordStretchingAlgorithm) {
        this.passwordStretchingAlgorithm = passwordStretchingAlgorithm;
    }
}
