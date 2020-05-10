package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class ApplyConferenceV1Request {
    @Schema(
        description = "The ID of the committee seat to apply to",
        example = "yBHlEK21Iq4mvXxhX7jc4iLi8mdSjRp1"
    )
    @NotBlank
    private String committeeSeatId;

    public String getCommitteeSeatId() {
        return committeeSeatId;
    }

    public void setCommitteeSeatId(String committeeSeatId) {
        this.committeeSeatId = committeeSeatId;
    }
}
