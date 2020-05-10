package org.diplomatiq.diplomatiqbackend.methods.entities.requests.subentities;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

public class CommitteeWithSeats {
    @Schema(
        description = "The name of the committee",
        example = "Security Council"
    )
    @NotBlank
    private String name;

    @Schema(
        description = "The code name of the committee",
        example = "SC"
    )
    @NotBlank
    private String codeName;

    @Schema(
        description = "The list of the represented countries in the committee as ISO3166-1 alpha-2 two letter country codes"
    )
    @NotEmpty
    private List<String> representedCountries;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCodeName() {
        return codeName;
    }

    public void setCodeName(String codeName) {
        this.codeName = codeName;
    }

    public List<String> getRepresentedCountries() {
        return representedCountries;
    }

    public void setRepresentedCountries(List<String> representedCountries) {
        this.representedCountries = representedCountries;
    }
}
