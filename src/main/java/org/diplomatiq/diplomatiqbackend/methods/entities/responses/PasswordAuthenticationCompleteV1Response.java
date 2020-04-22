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
        description = "The ID of the created authentication session as UTF-8 bytes, encrypted with the SRP session " +
            "key (K), as a Base64 string (in DiplomatiqAEAD format = AES-GCM without padding, serialized to binary " +
            "`[1-byte ivLength | 4-byte aadLength (big-endian) | 4-byte ciphertextLength (big-endian) | 1-byte " +
            "tagLength | ivLength-byte initialization vector | aadLength-byte additional authenticated data | " +
            "ciphertextLength-byte ciphertext | tagLength-byte authentication tag]`)",
        example = "DAAAAAAAAAAgEDdtnXdd+ZQgFJ+l0TeYcbA0aG/hNgsMSR3iDZUyHfemF6//n0ceGuNwwypOOMpr5kegP2isqfhuAocdbw=="
    )
    @NotBlank
    private String authenticationSessionIdAeadBase64;

    public PasswordAuthenticationCompleteV1Response(@NotBlank String serverProofBase64,
                                                    @NotBlank String authenticationSessionIdAeadBase64) {
        this.serverProofBase64 = serverProofBase64;
        this.authenticationSessionIdAeadBase64 = authenticationSessionIdAeadBase64;
    }

    public String getServerProofBase64() {
        return serverProofBase64;
    }

    public String getAuthenticationSessionIdAeadBase64() {
        return authenticationSessionIdAeadBase64;
    }
}
