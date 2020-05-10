package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class CancelConferenceV1Request {
    @Schema(
        description = "The ID of the conference to cancel",
        example = "iiZsbKfcN3WMSP9oE45OfkD6xc80gY5q"
    )
    @NotBlank
    private String conferenceId;

    public String getConferenceId() {
        return conferenceId;
    }

    public void setConferenceId(String conferenceId) {
        this.conferenceId = conferenceId;
    }
}
