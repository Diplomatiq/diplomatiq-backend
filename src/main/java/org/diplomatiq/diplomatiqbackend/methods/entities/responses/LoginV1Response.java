package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class LoginV1Response {
    @Schema(
        description = "The ID of the created device",
        example = "ljprfvlp3Zo6x1owl43M22FdZA6HH7Kn"
    )
    @NotBlank
    private String deviceId;

    @Schema(
        description = "The device key, encrypted with the authentication session key, as a Base64 string (in " +
            "DiplomatiqAEAD format = AES-GCM without padding, serialized to binary `[1-byte ivLength | 4-byte " +
            "aadLength (big-endian) | 4-byte ciphertextLength (big-endian) | 1-byte tagLength | ivLength-byte " +
            "initialization vector | aadLength-byte additional authenticated data | ciphertextLength-byte ciphertext " +
            "| tagLength-byte authentication tag]`)",
        example = "DAAAAAAAAAAgEKCC9jgnAcs4ArZw/3OlUTwPVhlzB7VNQkQ2C3wSAWfLOfQIt1Dw04aTsMt3qr8kftBjPzXi3Rtm5+hX9A=="
    )
    @NotBlank
    private String deviceKeyAeadBase64;

    @Schema(
        description = "The session token, encrypted with the authentication session key, as a Base64 string (in " +
            "DiplomatiqAEAD format = AES-GCM without padding, serialized to binary `[1-byte ivLength | 4-byte " +
            "aadLength (big-endian) | 4-byte ciphertextLength (big-endian) | 1-byte tagLength | ivLength-byte " +
            "initialization vector | aadLength-byte additional authenticated data | ciphertextLength-byte ciphertext " +
            "| tagLength-byte authentication tag]`)",
        example = "DAAAAAAAAAAgENEP4WCNTvOlJNAFxz62Q8oit2Y/3u9MU84utT7sZN0VhrDQ8U+5qBkArOyEbDnTbHrIGf5M981tyHHr5w=="
    )
    @NotBlank
    private String sessionTokenAeadBase64;

    public LoginV1Response(@NotBlank String deviceId, @NotBlank String deviceKeyAeadBase64,
                           @NotBlank String sessionTokenAeadBase64) {
        this.deviceId = deviceId;
        this.deviceKeyAeadBase64 = deviceKeyAeadBase64;
        this.sessionTokenAeadBase64 = sessionTokenAeadBase64;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getDeviceKeyAeadBase64() {
        return deviceKeyAeadBase64;
    }

    public String getSessionTokenAeadBase64() {
        return sessionTokenAeadBase64;
    }
}
