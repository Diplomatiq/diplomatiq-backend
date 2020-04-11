package org.diplomatiq.diplomatiqbackend.filters.signature;

public final class RequestSigningAlgorithm {

    public enum DiplomatiqRequestSigningAlgorithm {
        DIPLOMAITQ_01_HMAC_SHA256("DIPLOMATIQ-01-HMAC-SHA256");

        public final String string;

        DiplomatiqRequestSigningAlgorithm(String string) {
            this.string = string;
        }
    }

    public static DiplomatiqRequestSigningAlgorithm fromString(String s) {
        switch (s) {
            case "DIPLOMATIQ-01-HMAC-SHA256":
                return DiplomatiqRequestSigningAlgorithm.DIPLOMAITQ_01_HMAC_SHA256;

            default:
                throw new IllegalArgumentException("unknown signature algorithm");
        }
    }

}
