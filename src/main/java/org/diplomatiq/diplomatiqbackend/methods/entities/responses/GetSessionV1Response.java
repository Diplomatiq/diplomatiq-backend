package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class GetSessionV1Response {
    @Schema(
        description = "The ID of the created session or the ID of the old session which is still valid for at least 1" +
            " minute, as UTF-8 bytes, encrypted with the device key, as a Base64 string (in DiplomatiqAEAD format = " +
            "AES-GCM without padding, serialized to binary `[1-byte ivLength | 4-byte aadLength (big-endian) | 4-byte" +
            " ciphertextLength (big-endian) | 1-byte tagLength | ivLength-byte initialization vector | aadLength-byte" +
            " additional authenticated data | ciphertextLength-byte ciphertext | tagLength-byte authentication tag]`)",
        example = "DAAAAAAAAAAgEKYuIUF+6ev+71yrVBe7WADBfv3EWm8/t+sYNo2tXPDCoow0hUKXmIh7IPizWQpN3HPp3zm73gkOAESjIA=="
    )
    @NotBlank
    private String sessionIdAeadBase64;

    public GetSessionV1Response(@NotBlank String sessionIdAeadBase64) {
        this.sessionIdAeadBase64 = sessionIdAeadBase64;
    }

    public String getSessionIdAeadBase64() {
        return sessionIdAeadBase64;
    }
}
