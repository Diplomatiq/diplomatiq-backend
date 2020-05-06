package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class GetUserIdentityV1Response {
    @Schema(
        description = "The email address of the user",
        example = "samsepi0l@diplomatiq.org"
    )
    @NotBlank
    private String emailAddress;

    @Schema(
        description = "The first name of the user",
        example = "Sam"
    )
    @NotBlank
    private String firstName;

    @Schema(
        description = "The last name of the user",
        example = "Sam"
    )
    @NotBlank
    private String lastName;

    public GetUserIdentityV1Response(@NotBlank String emailAddress, @NotBlank String firstName,
                                     @NotBlank String lastName) {
        this.emailAddress = emailAddress;
        this.firstName = firstName;
        this.lastName = lastName;
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
}
