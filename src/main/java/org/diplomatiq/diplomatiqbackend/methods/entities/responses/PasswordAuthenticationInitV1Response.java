package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import javax.validation.constraints.NotBlank;

public class PasswordAuthenticationInitV1Response {
    @NotBlank
    private String serverEphemeralBase64;

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
