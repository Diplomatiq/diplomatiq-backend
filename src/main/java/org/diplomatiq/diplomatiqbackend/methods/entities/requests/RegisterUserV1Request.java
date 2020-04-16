package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

public class RegisterUserV1Request {
    @NotBlank
    @Email
    private String emailAddress;

    @NotBlank
    private String firstName;

    @NotBlank
    private String lastName;

    @NotBlank
    private String srpSaltBase64;

    @NotBlank
    private String srpVerifierBase64;

    @NotBlank
    private String passwordStretchingAlgorithm;

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

    public String getPasswordStretchingAlgorithm() {
        return passwordStretchingAlgorithm;
    }

    public void setPasswordStretchingAlgorithm(String passwordStretchingAlgorithm) {
        this.passwordStretchingAlgorithm = passwordStretchingAlgorithm;
    }
}
