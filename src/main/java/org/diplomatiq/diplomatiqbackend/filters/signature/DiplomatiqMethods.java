package org.diplomatiq.diplomatiqbackend.filters.signature;

import java.util.Collections;
import java.util.Set;

public class DiplomatiqMethods {
    public static final Set<String> AllowedRequestMethods = Collections.unmodifiableSet(
        Set.of(
            "GET",
            "POST",
            "PUT"
        )
    );
}
