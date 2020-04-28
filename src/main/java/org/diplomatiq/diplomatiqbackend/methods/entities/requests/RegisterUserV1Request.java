package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

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
    @Size(min = 1, max = 200)
    @NotBlank
    private String firstName;

    @Schema(
        description = "The last name(s) of the user",
        example = "Sepiol"
    )
    @Size(min = 1, max = 200)
    @NotBlank
    private String lastName;

    @Schema(
        description = "The SRP salt (s) as a Hex string",
        example = "85dcccb8f6af8b1f8b0e73ab476c0fce05d554bcc53461017558bc11ac8e87f8"
    )
    @NotBlank
    private String srpSaltHex;

    @Schema(
        description = "The SRP verifier (s) as a Hex string",
        example = "ab7a57cfb5374a779f4f2658feefbf1407120018cbdf78819532aa3a4b7fbd4302d5450e448968ad791b7441b0a4824b3c" +
            "d2b9f30ff8ec43ff7555e8453f6b82824c88137f4a9f475895bc7a0ba5bd876bba950102aa11a63267f6a09c4d1b7dd3c296ed19" +
            "f712cee65f3214efb47f350d3e6a35dd3dba88722fc4089a9512cee95b687a967d13cfca533ae66106d4aa3c709737377d85f170" +
            "f0b956a8c00ec9e5a53bcc7ee2159f5c408fec5a490aeb7ff2b1a6816f27a0d7e83211ebca82ffabf9399430d1c07033f007a8bf" +
            "3e365d6cdde0abf3aa0ce574f32ba3f63bc55a75d9cf89b52f03cbdb7eecd2598f6156613d0e2aa5b1bf8132db27865d8c571626" +
            "599a7dfa21952a5ec5e035612f28829a80edb2209091864b1e0c5569cfb7cb3bdb2d4071f60642bdd630879acbedd88db3f60745" +
            "683fb6aa5585d98dd69acc9938f9b19c5432a691ec1480f0a2fbffd7dbf7473d8bdd2df9ee118575dbcab3333f4a11dffc8dee34" +
            "21844edf06cb30642df01e0997be93cb19bc160e75e15b9b92e525601070f1a4c23bba6caa86a928b17078220dd2cf2e99aa9c8d" +
            "b3d9101a4eb9f319424bcd4a040cbc2e398f17cc5587be54a957db654272666aeb4020899a41f69e77734a5df06b7f75a6807890" +
            "4e5a5111e1ffe70f3e63ee69ad6acefdde9ba04b276653c496c72c70792a8c9057628acc64199134a2d9ba18b5fc2375d2ffec33" +
            "5170719de58329a39ee31e7b16c941a010c62fad46aded44b393e0e65d9ae54037d47a1a3ad6951eeff58a4ea009f897d6b0163e" +
            "773478b3014ac5c1769bb9ac32b2b98b862ff38bfcfc267f09d61d072b6c9b56b462c9b1c25e77165c8c8ae50b73d78ba8cf98d7" +
            "4d7fcae862dffb294e71a6873369c261690ed3a36b41e66152403a4d37a81b959290796c8ce9f81abddef0c5db411dcd8bbae08a" +
            "fc2b35dc13b2d5032c1d5be6cb927646177061f7a8e16c81a268dd4fdd3e7f488917814e749b9f5c2934da774f2c26d5a530341e" +
            "3437855ada4a7513d199791f795e87dd4d77c80ffefec0b78ee99bca35c4955e9a4c7813339bc4785cbe7ea242b7693a847ad01a" +
            "cb565e0576dac0cc482292be648416a0948cdf6777b075da7d265387bdfd198d038c30dbbec3bdd70385074ca28161c9d502bb4c" +
            "82e59571492a8dd12d76e09bd45c6d2e1782474282576a624af10c91211291b2d2788440f20e754481a8b0d3d733efa1c0c2a4cd" +
            "933e91559667f089675010dce1f341a37e911bb96c89fe7c280527a54b2889ec4051977466a927bc4bf0f271026fae793be49d00" +
            "8859fa21a13f4823b9800054c58668cf9f0ab587b58646938a797f5784b967d092b2e8b55961523b5430e7309307f5f0e3777d82" +
            "79c81fe1cce5358fb2c195dbdb7ded6bf03bdfb9b5c71810c9d913e452ee1906f76fd19b436734"
    )
    @NotBlank
    private String srpVerifierHex;

    @Schema(
        description = "The hash function used for calculating the exponent of the SRP verifier (v)",
        example = "Argon2_v1",
        required = true
    )
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

    public String getSrpSaltHex() {
        return srpSaltHex;
    }

    public void setSrpSaltHex(String srpSaltHex) {
        this.srpSaltHex = srpSaltHex;
    }

    public String getSrpVerifierHex() {
        return srpVerifierHex;
    }

    public void setSrpVerifierHex(String srpVerifierHex) {
        this.srpVerifierHex = srpVerifierHex;
    }

    public PasswordStretchingAlgorithm getPasswordStretchingAlgorithm() {
        return passwordStretchingAlgorithm;
    }

    public void setPasswordStretchingAlgorithm(PasswordStretchingAlgorithm passwordStretchingAlgorithm) {
        this.passwordStretchingAlgorithm = passwordStretchingAlgorithm;
    }
}
