package org.diplomatiq.diplomatiqbackend.methods.entities.responses;

import io.swagger.v3.oas.annotations.media.Schema;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;

import javax.validation.constraints.NotBlank;

public class PasswordAuthenticationInitV1Response {
    @Schema(
        description = "The SRP server ephemeral (B) as a Hex string",
        example = "76a88bb09a87eed7987503cc1149c1f36f9cb69aeedc2e0b74f7b8ac7c83380f8241f05cea7acab8bf36de8cc6c922cd51" +
            "d3bbf24c5eeb7f11c24fd84e7c36277fa1f3d67d17bd3f41e2223eca061481f3e3c946ee6e6f1581c0df6e0faa15305b59d26e4d" +
            "b3d728a62fc83cc2d8397c7760632edc6dbe03fdcdf0ff212015c6ce5fab2d05d62bacb206da294e7034199ebe34a9661fb1449f" +
            "fe743dd0b3e52e6155d36a8c3d5a249f175b3366e79cb26eab0036df453c3dcc23fe46f83506b6be3dd4bb3615e54d55d6a97cb5" +
            "b1ff6615e9751f5f1d24bbabae485968a500c8f325ed06bcb347f0d3797dfb0d8563e2cc73eb64d3f21435f8a5dd38a6f30bdd5c" +
            "403e354bc9cef2f105fc06d021a27058c27d488eab5b79a76e18aa25c6f68869237f9953db39d0022f4a82d2b0abcd31398eb8fb" +
            "e3b0fd1013e4adf3d880ea4481979e1e0dd61505ae65a1501a26ea48baa209e43596780880925901f5462d58441eabe729f5968d" +
            "970c45d20f50a38600d478392d5f9aa72ac4c7ac0e30cfb67f63932d5a8d6bc92a2a90d1d67e0268bc247589aac0afe487ee5f48" +
            "0ba7382728e36bb18fa6f1ab2e8e4013c5e6ea4aa6e93b0d8c97bb88233070ecbc5d46eaabf6aad2cd11057ae0f4dcaafe4abd7f" +
            "96e05fc62efe2c2b5b602d2e1b6ceca212b5139b194e01f9a9ef3d298c4690d65ee195a478dd08240e4fbbead20ba078ff7d90b2" +
            "d74b7bdd48b3068a9374bd34f06c62673e604d3b0d6831c0b4f50ddfd3d02151816b365c3c9f67c6493df578dcabc28d8d016c46" +
            "83375bea00aa8fc6be0048283e67ffaf019c786691598d81505bb44d7c6228826b998239288298b8da1becb99d823a50a15183d1" +
            "5b97293c51c26036d94da7700894b4f294b1d4129df7617f0761a1c8c089c3c66019202499eab7bb4f0f50f4daf2e502dc7b3b0b" +
            "302be10ed66ca94721f31fa09708b29db6daa441e3a2ab68ae1aa0f8a5b8641b51b2aa4b63078ece58a32719b5f08d9291850c33" +
            "35aec6d6835c31cb2b7b5b623f0555af78afda0f955a1e1b8a0762ca64ded428a8dde12a255ce79f49cc68fbd98e970c3d4409f5" +
            "8b9adf6c7be17d00f1a4363c69ddd87307e5226ff42753c8446991026515f960242362c88c89ee3a3b6ee42c61f318bd0166fad1" +
            "c07301fb673c48651a687c6ab8ab36b9fe3cd3973e820c671406124c7601ed727d57b2f462e2d9fd1880bebafa15ebce60a49b22" +
            "b9d8a14721ef3078fcb73673a81c5d439cb464b70d2dd56aef018d63479f151f7cc45a7dbee60b55069d0e3420c126c3cf8beee7" +
            "ffcda7715c7f4a67a8113a14178ae05d00369c592254b21ea5de31b8361465225b86c9553f50ed4516db851cbefd4430438cb85b" +
            "a7b51080d84d8534962b0ddbc41bcfaddcf310396d7ace63b0ef0b877cc3ec2c3eb35ea66c57bc"
    )
    @NotBlank
    private String serverEphemeralHex;

    @Schema(
        description = "The SRP salt (s) as a Hex string",
        example = "e4c738d56e022944e9ca6d66a6fdad1b96bc251abc1375f287cf286b151365f5"
    )
    @NotBlank
    private String srpSaltHex;

    @Schema(
        description = "The hash function used for calculating the exponent of the SRP verifier (v)",
        example = "Argon2_v1"
    )
    @NotBlank
    private PasswordStretchingAlgorithm passwordStretchingAlgorithm;

    public PasswordAuthenticationInitV1Response(@NotBlank String serverEphemeralHex,
                                                @NotBlank String srpSaltHex,
                                                PasswordStretchingAlgorithm passwordStretchingAlgorithm) {
        this.serverEphemeralHex = serverEphemeralHex;
        this.srpSaltHex = srpSaltHex;
        this.passwordStretchingAlgorithm = passwordStretchingAlgorithm;
    }

    public String getServerEphemeralHex() {
        return serverEphemeralHex;
    }

    public String getSrpSaltHex() {
        return srpSaltHex;
    }

    public PasswordStretchingAlgorithm getPasswordStretchingAlgorithm() {
        return passwordStretchingAlgorithm;
    }
}
