package org.diplomatiq.diplomatiqbackend.methods.entities.responses.subentities;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

public class CommitteeWithEmptySeats {
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
        description = "The list of seats (represented countries) which are still empty"
    )
    @NotEmpty
    private List<EmptyCommitteeSeat> emptyCommitteeSeats;

    public CommitteeWithEmptySeats(@NotBlank String name, @NotBlank String codeName,
                                   @NotEmpty List<EmptyCommitteeSeat> emptyCommitteeSeats) {
        this.name = name;
        this.codeName = codeName;
        this.emptyCommitteeSeats = emptyCommitteeSeats;
    }

    public String getName() {
        return name;
    }

    public String getCodeName() {
        return codeName;
    }

    public List<EmptyCommitteeSeat> getEmptyCommitteeSeats() {
        return emptyCommitteeSeats;
    }
}
