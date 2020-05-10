package org.diplomatiq.diplomatiqbackend.methods.entities.responses.subentities;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class EmptyCommitteeSeat {
    @Schema(
        description = "The ID of the committee seat",
        example = "tAdVVQVrkwdVZXkgxyUjrksi6I8UTriR"
    )
    @NotBlank
    private String committeeSeatId;

    @Schema(
        description = "The represented country as ISO3166 alpha2 country code",
        example = "HU"
    )
    @NotBlank
    private String representedCountry;

    public EmptyCommitteeSeat(@NotBlank String committeeSeatId, @NotBlank String representedCountry) {
        this.committeeSeatId = committeeSeatId;
        this.representedCountry = representedCountry;
    }

    public String getCommitteeSeatId() {
        return committeeSeatId;
    }

    public String getRepresentedCountry() {
        return representedCountry;
    }
}
