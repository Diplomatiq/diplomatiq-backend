package org.diplomatiq.diplomatiqbackend.filters.signature;

public final class AuthenticationScheme {

    public enum DiplomatiqAuthenticationScheme {
        SignedSession("SignedSession");

        public final String string;

        DiplomatiqAuthenticationScheme(String string) {
            this.string = string;
        }
    }

    public static DiplomatiqAuthenticationScheme fromString(String s) {
        switch (s) {
            case "SignedSession":
                return DiplomatiqAuthenticationScheme.SignedSession;

            default:
                throw new IllegalArgumentException("unknown authentication scheme: " + s);
        }
    }

}
