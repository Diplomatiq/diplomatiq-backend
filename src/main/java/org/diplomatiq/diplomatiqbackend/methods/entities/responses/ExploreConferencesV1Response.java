package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import io.swagger.v3.oas.annotations.media.Schema;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.subentities.CommitteeWithEmptySeats;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

public class ExploreConferencesV1Response {
    @Schema(
        description = "The full name of the conference",
        example = "Budapest International Model United Nations"
    )
    @NotBlank
    private String conferenceName;

    @Schema(
        description = "The code name of the conference",
        example = "BIMUN"
    )
    @NotBlank
    private String conferenceCodeName;

    @Schema(
        description = "The start date of the conference",
        example = "2015-04-10"
    )
    @NotBlank
    private String conferenceFrom;

    @Schema(
        description = "The end date of the conference",
        example = "2015-04-14"
    )
    @NotBlank
    private String conferenceTo;

    @Schema(
        description = "The country of the conference address as an ISO3166-1 alpha-2 two letter country code",
        example = "HU"
    )
    @NotBlank
    private String conferenceCountry;

    @Schema(
        description = "The city of the conference address",
        example = "Budapest"
    )
    @NotBlank
    private String conferenceCity;

    @Schema(
        description = "The address of the conference",
        example = "Reáltanoda utca 7."
    )
    @NotBlank
    private String conferenceAddress;

    @Schema(
        description = "The postal code of the conference address",
        example = "1053"
    )
    @NotBlank
    private String conferencePostalCode;

    @Schema(
        description = "The list of committees which have empty seats, with empty seats"
    )
    @NotEmpty
    private List<CommitteeWithEmptySeats> committeesWithEmptySeats;

    public ExploreConferencesV1Response(@NotBlank String conferenceName, @NotBlank String conferenceCodeName,
                                        @NotBlank String conferenceFrom, @NotBlank String conferenceTo,
                                        @NotBlank String conferenceCountry, @NotBlank String conferenceCity,
                                        @NotBlank String conferenceAddress, @NotBlank String conferencePostalCode,
                                        @NotEmpty List<CommitteeWithEmptySeats> committeesWithEmptySeats) {
        this.conferenceName = conferenceName;
        this.conferenceCodeName = conferenceCodeName;
        this.conferenceFrom = conferenceFrom;
        this.conferenceTo = conferenceTo;
        this.conferenceCountry = conferenceCountry;
        this.conferenceCity = conferenceCity;
        this.conferenceAddress = conferenceAddress;
        this.conferencePostalCode = conferencePostalCode;
        this.committeesWithEmptySeats = committeesWithEmptySeats;
    }

    public String getConferenceName() {
        return conferenceName;
    }

    public String getConferenceCodeName() {
        return conferenceCodeName;
    }

    public String getConferenceFrom() {
        return conferenceFrom;
    }

    public String getConferenceTo() {
        return conferenceTo;
    }

    public String getConferenceCountry() {
        return conferenceCountry;
    }

    public String getConferenceCity() {
        return conferenceCity;
    }

    public String getConferenceAddress() {
        return conferenceAddress;
    }

    public String getConferencePostalCode() {
        return conferencePostalCode;
    }

    public List<CommitteeWithEmptySeats> getCommitteesWithEmptySeats() {
        return committeesWithEmptySeats;
    }
}
