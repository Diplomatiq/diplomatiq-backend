package org.diplomatiq.diplomatiqbackend.methods.entities.responses.subentities;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class SeatWithDelegate {
    @Schema(
        description = "The ISO3166-1 alpha-2 two letter country code of the represented country",
        example = "HU"
    )
    @NotBlank
    private String representedCountry;

    @Schema(
        description = "The email address of the representing delegate",
        example = "samsepi0l@diplomatiq.org"
    )
    @NotBlank
    private String delegateEmailAddress;

    @Schema(
        description = "The first name of the representing delegate",
        example = "Sam"
    )
    @NotBlank
    private String delegateFirstName;

    @Schema(
        description = "The last name of the representing delegate",
        example = "Sepiol"
    )
    @NotBlank
    private String delegateLastName;

    public SeatWithDelegate(@NotBlank String representedCountry, @NotBlank String delegateEmailAddress,
                            @NotBlank String delegateFirstName, @NotBlank String delegateLastName) {
        this.representedCountry = representedCountry;
        this.delegateEmailAddress = delegateEmailAddress;
        this.delegateFirstName = delegateFirstName;
        this.delegateLastName = delegateLastName;
    }

    public String getRepresentedCountry() {
        return representedCountry;
    }

    public String getDelegateEmailAddress() {
        return delegateEmailAddress;
    }

    public String getDelegateFirstName() {
        return delegateFirstName;
    }

    public String getDelegateLastName() {
        return delegateLastName;
    }
}
