package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class GetSessionV1Request {
    @Schema(
        description = "The session token, encrypted with the device key, as a Base64 string (in DiplomatiqAEAD format" +
            " = AES-GCM without padding, serialized to binary `[1-byte ivLength | 4-byte aadLength (big-endian) | " +
            "4-byte ciphertextLength (big-endian) | 1-byte tagLength | ivLength-byte initialization vector | " +
            "aadLength-byte additional authenticated data | ciphertextLength-byte ciphertext | tagLength-byte " +
            "authentication tag]`)",
        example = "DAAAAAAAAAAgENEP4WCNTvOlJNAFxz62Q8oit2Y/3u9MU84utT7sZN0VhrDQ8U+5qBkArOyEbDnTbHrIGf5M981tyHHr5w=="
    )
    @NotBlank
    private String sessionTokenAeadBase64;

    public String getSessionTokenAeadBase64() {
        return sessionTokenAeadBase64;
    }

    public void setSessionTokenAeadBase64(String sessionTokenAeadBase64) {
        this.sessionTokenAeadBase64 = sessionTokenAeadBase64;
    }
}
