package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class GetDeviceContainerKeyV1Response {
    @Schema(
        description = "The key of the device container with the given ID.",
        example = "LeaSiXVzlbFewme4fypIawerhghlpAFePK3S10BbWHg="
    )
    @NotBlank
    private String deviceContainerKeyBase64;

    public GetDeviceContainerKeyV1Response(@NotBlank String deviceContainerKeyBase64) {
        this.deviceContainerKeyBase64 = deviceContainerKeyBase64;
    }

    public String getDeviceContainerKeyBase64() {
        return deviceContainerKeyBase64;
    }
}
