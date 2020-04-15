package org.diplomatiq.diplomatiqbackend.filters.signature;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class DiplomatiqHeaders {
    public static final Map<String, Set<String>> RequiredSignedSessionV1Headers = Collections.unmodifiableMap(
        Map.ofEntries(
            Map.entry(
                "GET", Collections.unmodifiableSet(
                    Set.of(
                        "ClientId",
                        "DeviceId",
                        "SessionId",
                        "SignedHeaders",
                        "Timestamp"
                    )
                )
            ),
            Map.entry(
                "POST", Collections.unmodifiableSet(
                    Set.of(
                        "ClientId",
                        "Content-Type",
                        "DeviceId",
                        "SessionId",
                        "SignedHeaders",
                        "Timestamp"
                    )
                )
            ),
            Map.entry(
                "PUT", Collections.unmodifiableSet(
                    Set.of(
                        "ClientId",
                        "Content-Type",
                        "DeviceId",
                        "SessionId",
                        "SignedHeaders",
                        "Timestamp"
                    )
                )
            )
        )
    );

    public static final Map<String, Set<String>> RequiredSignedAuthenticationSessionV1Headers =
        Collections.unmodifiableMap(
            Map.ofEntries(
                Map.entry(
                    "GET", Collections.unmodifiableSet(
                        Set.of(
                            "ClientId",
                            "AuthenticationSessionId",
                            "SignedHeaders",
                            "Timestamp"
                        )
                    )
                ),
                Map.entry(
                    "POST", Collections.unmodifiableSet(
                        Set.of(
                            "ClientId",
                            "Content-Type",
                            "AuthenticationSessionId",
                            "SignedHeaders",
                            "Timestamp"
                        )
                    )
                ),
                Map.entry(
                    "PUT", Collections.unmodifiableSet(
                        Set.of(
                            "ClientId",
                            "Content-Type",
                            "AuthenticationSessionId",
                            "SignedHeaders",
                            "Timestamp"
                        )
                    )
                )
            )
        );
}
