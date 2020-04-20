package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;

public class PasswordAuthenticationCompleteV1Response {
    @Schema(
        description = "The SRP server proof (M2) as a Base64 string",
        example = "k37idS0tChjuoufUxaoN0N9Ulw9MmfwTx1xds7ukVkM="
    )
    @NotBlank
    private String serverProofBase64;

    @Schema(
        description = "The ID of the authentication session encrypted with the SRP session key (K) as a Base64 string (in DiplomatiqAEAD format = encrypted by AES-GCM, serialized to binary `[12-byte initialization vector | ciphertext | 16-byte authentication tag]`)",
        example = "Uf+kZyIfSL8GUnldFFYzd9D0QK1VeWFUJ2OVoa2bZQ1J9QQl/wfb7+BNpPZ1RxuF6dsyfEE8rm/VSeD9"
    )
    @NotBlank
    private String encryptedAuthenticationSessionIdBase64;

    public PasswordAuthenticationCompleteV1Response(@NotBlank String serverProofBase64,
                                                    @NotBlank String encryptedAuthenticationSessionIdBase64) {
        this.serverProofBase64 = serverProofBase64;
        this.encryptedAuthenticationSessionIdBase64 = encryptedAuthenticationSessionIdBase64;
    }

    public String getServerProofBase64() {
        return serverProofBase64;
    }

    public String getEncryptedAuthenticationSessionIdBase64() {
        return encryptedAuthenticationSessionIdBase64;
    }
}
