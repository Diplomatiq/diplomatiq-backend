package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class PasswordAuthenticationInitV1Response {
    @Schema(
        description = "The SRP server ephemeral (B) as a Base64 string",
        example = "cJ80BzjmLkYYRjSs0s18hhp9ksX96etDrBICJqDrZgHuXRoLkv+2JUFw2R+0UcPAK7+LQfnn4+iF1wnw3EgIBI5ZXGhEiiERtF7vqh4takgU2ZrgOKXyNxx1OzEsUpytpmsj5lEsfvgUaD9M/ipMVBPENOIbxonYafyWkUG4SmE="
    )
    @NotBlank
    private String serverEphemeralBase64;

    @Schema(
        description = "The SRP salt (s) as a Base64 string",
        example = "VvyPbq9KiilnQf+rzKvW167aglv/z+YEdddcCSMEqb8="
    )
    @NotBlank
    private String srpSaltBase64;

    public PasswordAuthenticationInitV1Response(@NotBlank String serverEphemeralBase64,
                                                @NotBlank String srpSaltBase64) {
        this.serverEphemeralBase64 = serverEphemeralBase64;
        this.srpSaltBase64 = srpSaltBase64;
    }

    public String getServerEphemeralBase64() {
        return serverEphemeralBase64;
    }

    public String getSrpSaltBase64() {
        return srpSaltBase64;
    }
}
