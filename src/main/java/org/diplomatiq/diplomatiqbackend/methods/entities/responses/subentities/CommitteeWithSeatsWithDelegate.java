package org.diplomatiq.diplomatiqbackend.methods.entities.responses.subentities;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

public class CommitteeWithSeatsWithDelegate {
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
        description = "The list of seats (represented countries) with the representing delegate"
    )
    @NotEmpty
    private List<SeatWithDelegate> seatsWithDelegate;

    public CommitteeWithSeatsWithDelegate(@NotBlank String name, @NotBlank String codeName,
                                          @NotEmpty List<SeatWithDelegate> seatsWithDelegate) {
        this.name = name;
        this.codeName = codeName;
        this.seatsWithDelegate = seatsWithDelegate;
    }

    public String getName() {
        return name;
    }

    public String getCodeName() {
        return codeName;
    }

    public List<SeatWithDelegate> getSeatsWithDelegate() {
        return seatsWithDelegate;
    }
}
