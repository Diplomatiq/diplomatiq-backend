package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.subentities.CommitteeWithSeats;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

public class OrganizeConferenceV1Request {
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
        description = "The list of the committees of the conference with seats"
    )
    @NotEmpty
    private List<CommitteeWithSeats> committeeList;

    public String getConferenceName() {
        return conferenceName;
    }

    public void setConferenceName(String conferenceName) {
        this.conferenceName = conferenceName;
    }

    public String getConferenceCodeName() {
        return conferenceCodeName;
    }

    public void setConferenceCodeName(String conferenceCodeName) {
        this.conferenceCodeName = conferenceCodeName;
    }

    public String getConferenceFrom() {
        return conferenceFrom;
    }

    public void setConferenceFrom(String conferenceFrom) {
        this.conferenceFrom = conferenceFrom;
    }

    public String getConferenceTo() {
        return conferenceTo;
    }

    public void setConferenceTo(String conferenceTo) {
        this.conferenceTo = conferenceTo;
    }

    public String getConferenceCountry() {
        return conferenceCountry;
    }

    public void setConferenceCountry(String conferenceCountry) {
        this.conferenceCountry = conferenceCountry;
    }

    public String getConferenceCity() {
        return conferenceCity;
    }

    public void setConferenceCity(String conferenceCity) {
        this.conferenceCity = conferenceCity;
    }

    public String getConferenceAddress() {
        return conferenceAddress;
    }

    public void setConferenceAddress(String conferenceAddress) {
        this.conferenceAddress = conferenceAddress;
    }

    public String getConferencePostalCode() {
        return conferencePostalCode;
    }

    public void setConferencePostalCode(String conferencePostalCode) {
        this.conferencePostalCode = conferencePostalCode;
    }

    public List<CommitteeWithSeats> getCommitteeList() {
        return committeeList;
    }

    public void setCommitteeList(List<CommitteeWithSeats> committeeList) {
        this.committeeList = committeeList;
    }
}
