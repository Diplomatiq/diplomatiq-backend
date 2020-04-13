package org.diplomatiq.diplomatiqbackend.filters.signature;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class DiplomatiqHeaders {
    public static final Map<String, Set<String>> RequiredSignedHeaders = Collections.unmodifiableMap(
        Map.ofEntries(
            Map.entry(
                "GET", Collections.unmodifiableSet(
                    Set.of(
                        "ClientId",
                        "DeviceId",
                        "EncryptedSessionId",
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
                        "EncryptedSessionId",
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
                        "EncryptedSessionId",
                        "SignedHeaders",
                        "Timestamp"
                    )
                )
            )
        )
    );
}
