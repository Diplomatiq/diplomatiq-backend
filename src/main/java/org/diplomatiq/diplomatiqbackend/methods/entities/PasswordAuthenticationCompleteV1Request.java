package org.diplomatiq.diplomatiqbackend.methods.entities;

public class PasswordAuthenticationCompleteV1Request {
    private final String emailAddress;
    private final String clientEphemeralBase64;
    private final String clientProofBase64;
    private final String serverEphemeralBase64;

    public PasswordAuthenticationCompleteV1Request(String emailAddress, String clientEphemeralBase64, String clientProofBase64,
                                                   String serverEphemeralBase64) {
        this.emailAddress = emailAddress;
        this.clientEphemeralBase64 = clientEphemeralBase64;
        this.clientProofBase64 = clientProofBase64;
        this.serverEphemeralBase64 = serverEphemeralBase64;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public String getClientEphemeralBase64() {
        return clientEphemeralBase64;
    }

    public String getClientProofBase64() {
        return clientProofBase64;
    }

    public String getServerEphemeralBase64() {
        return serverEphemeralBase64;
    }
}
