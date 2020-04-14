package org.diplomatiq.diplomatiqbackend.methods.entities;

public class PasswordAuthenticationInitV1Response {
    private final String serverEphemeralBase64;
    private final String srpSaltBase64;

    public PasswordAuthenticationInitV1Response(String serverEphemeralBase64, String srpSaltBase64) {
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
