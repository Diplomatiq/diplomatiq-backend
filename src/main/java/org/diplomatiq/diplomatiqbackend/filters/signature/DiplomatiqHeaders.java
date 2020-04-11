package org.diplomatiq.diplomatiqbackend.filters.signature;

import java.util.Collections;
import java.util.Set;

public class DiplomatiqHeaders {
    public static final Set<String> RequiredSignedHeaders = Collections.unmodifiableSet(
        Set.of(
            "ClientId",
            "DeviceId",
            "EncryptedSessionId",
            "SignedHeaders",
            "Timestamp"
        )
    );
}
