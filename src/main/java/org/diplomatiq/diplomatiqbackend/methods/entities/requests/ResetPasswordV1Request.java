package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;

import javax.validation.constraints.NotBlank;

public class ResetPasswordV1Request {
    @Schema(
        description = "The password reset key the user received in email",
        example = "GByslDchKVGE5JZ6xagTa7nwRIkI7Ql1pP56kb1gst18A14diSEDpRvi0QPHZRSUsJKAPgBnSDnIadmLZyXV8JfbhEl4nKLWzzQVpKNN5oMkqcQ1mWqOJTvLD17x2TCjPlGyJ1hpwoF8jyIJPJT6g7"
    )
    @NotBlank
    private String passwordResetKey;

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
        description = "The hash function used for calculating the exponent of the SRP verifier (v)",
        example = "Argon2_v1"
    )
    @NotBlank
    private PasswordStretchingAlgorithm passwordStretchingAlgorithm;

    public String getPasswordResetKey() {
        return passwordResetKey;
    }

    public void setPasswordResetKey(String passwordResetKey) {
        this.passwordResetKey = passwordResetKey;
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
