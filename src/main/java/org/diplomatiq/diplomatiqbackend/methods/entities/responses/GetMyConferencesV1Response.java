package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class GetMyConferencesV1Response {
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
        description = "The name of the committee the user represents in",
        example = "Security Council"
    )
    @NotBlank
    private String committeeName;

    @Schema(
        description = "The code name of the committee the user represents in",
        example = "SC"
    )
    @NotBlank
    private String committeeCodeName;

    @Schema(
        description = "The represented country of the user as an ISO3166-1 alpha-2 two letter country code",
        example = "HU"
    )
    @NotBlank
    private String representedCountry;

    @Schema(
        description = "The ID of the represented committee seat",
        example = "eoynxOshSoyoosuTZUqqtqD3VJhuxFXp"
    )
    @NotBlank
    private String committeeSeatId;

    public GetMyConferencesV1Response(@NotBlank String conferenceName, @NotBlank String conferenceCodeName,
                                      @NotBlank String conferenceFrom, @NotBlank String conferenceTo,
                                      @NotBlank String conferenceCountry, @NotBlank String conferenceCity,
                                      @NotBlank String conferenceAddress, @NotBlank String conferencePostalCode,
                                      @NotBlank String committeeName, @NotBlank String committeeCodeName,
                                      @NotBlank String representedCountry, @NotBlank String committeeSeatId) {
        this.conferenceName = conferenceName;
        this.conferenceCodeName = conferenceCodeName;
        this.conferenceFrom = conferenceFrom;
        this.conferenceTo = conferenceTo;
        this.conferenceCountry = conferenceCountry;
        this.conferenceCity = conferenceCity;
        this.conferenceAddress = conferenceAddress;
        this.conferencePostalCode = conferencePostalCode;
        this.committeeName = committeeName;
        this.committeeCodeName = committeeCodeName;
        this.representedCountry = representedCountry;
        this.committeeSeatId = committeeSeatId;
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

    public String getCommitteeName() {
        return committeeName;
    }

    public String getCommitteeCodeName() {
        return committeeCodeName;
    }

    public String getRepresentedCountry() {
        return representedCountry;
    }

    public String getCommitteeSeatId() {
        return committeeSeatId;
    }
}
