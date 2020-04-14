package org.diplomatiq.diplomatiqbackend.methods.entities;

public class RegisterUserV1Request {

    private final String emailAddress;
    private final String firstName;
    private final String lastName;
    private final String srpSaltHex;
    private final String srpVerifierHex;

    public RegisterUserV1Request(String emailAddress, String firstName, String lastName, String srpSaltHex,
                                 String srpVerifierHex) {
        this.emailAddress = emailAddress;
        this.firstName = firstName;
        this.lastName = lastName;
        this.srpSaltHex = srpSaltHex;
        this.srpVerifierHex = srpVerifierHex;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getSrpSaltHex() {
        return srpSaltHex;
    }

    public String getSrpVerifierHex() {
        return srpVerifierHex;
    }
}
