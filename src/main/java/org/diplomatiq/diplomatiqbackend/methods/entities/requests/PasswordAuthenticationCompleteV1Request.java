package org.diplomatiq.diplomatiqbackend.methods.entities.requests;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

public class PasswordAuthenticationCompleteV1Request {
    @Schema(
        description = "The email address of the user",
        example = "samsepi0l@diplomatiq.org"
    )
    @NotBlank
    @Email
    private String emailAddress;

    @Schema(
        description = "The SRP client ephemeral (A) as a Hex string",
        example = "cd17fc83d4efdc10516892f222903cd13796149216750c488c5434465ce539cabfd3c28e19e0199bcd42883734fb8fc2a8" +
            "770dd262200cf0930e363e1a2dcd545b187cf72aecbfabb9cf6a9192c3973a1398a5eb14f493f9f6cb31a5ba20bddc1fdf525c52" +
            "803ab5f899f9196168b52e9d5119f4ce30dbc3e0f66a8c777593ebfa3cbdee92ea73a4920bdb10c7b75c7b9490c84b906cabd3bc" +
            "ac777aca3e3b5291ba1e14cb72e2893009f09eaa5cfaff4566189ec5394f424cabb989262cef59a18ebc588301fe4ca1c7014eb5" +
            "d0c9ffc730fb5aaf178de1b636545eaffa7682afecfbf6e875ad007b0c38c348646187a2f9395c9a43bce1c9b6b03bdc03c83cb7" +
            "af87db46f3cdcee81d8df8a55b791947c08671fe87a59d851b4bbc507173cc776200b2eac2410c5d993a1f2c5171e70278a78931" +
            "35779609c418b0c55524018aa8a9c16864f9ba3fcb9cbe02780d0c3be070779989d521cea5a87b816830945dc486418fb8fe6c1d" +
            "d0783c14e1813f7d2560c006db00a65bf34911a93dc54cf53224db7c2e6cb1a8e5a20e82698a4748572a511a7725cd040608328d" +
            "00ccd15d2668a037402bf60c72cc90cf442bf2a87be2b26c8bda193151bc773718aec1da6e952466af88657273bae47ddd9ce596" +
            "bf5210f213f870a233d4d3c2ac2903cf844fc934378cfb16915d2ff89421fe1de984e939365a94ec041772293b1e426955eb3cfa" +
            "e2483804ae06ada2695c79d7efbaff5a16849c46baa839a6e08ea5c48b5ab38f596fa0a12d62539e9d5a943e54fb04b7dce8ca02" +
            "636965f571f4d04ae0afbff7a2f0e38b414d4d4599f049f0488881b3f32bc722af6dc603c91682e2209d2f2d1b65f6aee2e85ff5" +
            "f41290f287e14dba3aff62cebdedf021a2b4b435af3a4ff6996beb6eef03f155bb2cd1d5808de68083d9ed97e343d057e90a5c69" +
            "72f25557fa7e482e51067f43e43b8f4a9d1692c065895b7c833068ef1a4e942dde18932bf4f0d68d1f67ffb84d6e0334bcdcb1f4" +
            "c13ac2db8f54b350a5321a4c15035fb0cf79b1131ffcf1b85e2d1ae3d624afd1a17aa4159cdbe6bfb187b99574801443b24d94d5" +
            "e489a8db908d39cda64e99a4494e759feb751884a42bae5eaf75e08959a4956de450de8d967f2d401e74483d5f793328cb259cbb" +
            "365b6c38287fd929aeee0c09f786fa3bee3e9ec3653f2b5995ea8c1fb72eb8b6eb657da9ca50410aa1eb22e73ba263ae67523c88" +
            "12fd1013fa07768f79cebbbb66116e860b4a452408a656fec0b85f877341d994453ae32f57444b38e566cc1a29101e07fee7697e" +
            "6162dffb05358ea4e356692d6889fd89de66bbcd90728b27ba85828fbfafe1ee10f0aff46e4ab90c1831bcef3409ab305f0527a6" +
            "3fd9392edef5cebe263ab20e90c02d8f5f338858701ab6102e40fe22806b7de73b7e0f2a7292f1"
    )
    @NotBlank
    private String clientEphemeralHex;

    @Schema(
        description = "The SRP client proof (M1) as a Hex string",
        example = "e6e805bf0135c0472c7f040dd1205b233fcb82b078ac81682a51f801653d5d27"
    )
    @NotBlank
    private String clientProofHex;

    @Schema(
        description = "The SRP server ephemeral (B) received previously, as a Hex string",
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

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public String getClientEphemeralHex() {
        return clientEphemeralHex;
    }

    public void setClientEphemeralHex(String clientEphemeralHex) {
        this.clientEphemeralHex = clientEphemeralHex;
    }

    public String getClientProofHex() {
        return clientProofHex;
    }

    public void setClientProofHex(String clientProofHex) {
        this.clientProofHex = clientProofHex;
    }

    public String getServerEphemeralHex() {
        return serverEphemeralHex;
    }

    public void setServerEphemeralHex(String serverEphemeralHex) {
        this.serverEphemeralHex = serverEphemeralHex;
    }
}
