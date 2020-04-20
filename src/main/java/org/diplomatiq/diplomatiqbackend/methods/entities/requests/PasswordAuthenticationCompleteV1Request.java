package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

public class PasswordAuthenticationCompleteV1Request {
    @Schema(
        description = "The email address of the user",
        example = "samsepi0l@diplomatiq.org"
    )
    @NotBlank
    @Email
    private String emailAddress;

    @Schema(
        description = "The SRP client ephemeral (A) as a Base64 string",
        example = "SBR9AT46Lgis4iKgq5FKftZ8cEskgHFrU/nSKSQ9FyVHPPRFGQRlhZf0h7D6i8fVRGcbJVY/CVutOEy7jaf1j38TyPqLudaq3l/gLfKI8rONcdUQNu3lKAJkX4LNchZTXAyXj5AjDg+HgWOmOM9XrRGWgWnCbkZ7juFOsspbFhQ="
    )
    @NotBlank
    private String clientEphemeralBase64;

    @Schema(
        description = "The SRP client proof (M1) as a Base64 string",
        example = "Ah0VRqGPkjkHuXUJE0ExbKA7rPnP1hsz9m2H4H6s/xg="
    )
    @NotBlank
    private String clientProofBase64;

    @Schema(
        description = "The SRP server ephemeral (B) received previously, as a Base64 string",
        example = "cJ80BzjmLkYYRjSs0s18hhp9ksX96etDrBICJqDrZgHuXRoLkv+2JUFw2R+0UcPAK7+LQfnn4+iF1wnw3EgIBI5ZXGhEiiERtF7vqh4takgU2ZrgOKXyNxx1OzEsUpytpmsj5lEsfvgUaD9M/ipMVBPENOIbxonYafyWkUG4SmE="
    )
    @NotBlank
    private String serverEphemeralBase64;

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
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
