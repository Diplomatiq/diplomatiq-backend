package org.diplomatiq.diplomatiqbackend.methods.entities;

public class PasswordAuthenticationInitV1Request {
    private final String emailAddress;

    public PasswordAuthenticationInitV1Request(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public String getEmailAddress() {
        return emailAddress;
    }
}
