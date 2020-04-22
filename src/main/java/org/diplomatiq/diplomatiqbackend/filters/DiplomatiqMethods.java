package org.diplomatiq.diplomatiqbackend.filters;

import java.util.Collections;
import java.util.Set;

public class DiplomatiqMethods {
    public static final Set<String> AllowedMethods = Collections.unmodifiableSet(
        Set.of(
            "GET",
            "POST",
            "PUT"
        )
    );
}
