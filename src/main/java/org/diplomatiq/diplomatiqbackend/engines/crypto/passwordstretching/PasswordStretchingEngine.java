package org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching;

import java.util.Collections;
import java.util.Map;

public class PasswordStretchingEngine {
    private static final Map<Integer, PasswordStretchingAlgorithm> passwordStretchingAlgorithmByVersionMap =
        Collections.unmodifiableMap(
            Map.ofEntries(
                Map.entry(1, PasswordStretchingAlgorithm.Argon2_v1)
            )
        );

    public static PasswordStretchingAlgorithm getLatestAlgorithm() {
        return passwordStretchingAlgorithmByVersionMap.get(
            Collections.max(passwordStretchingAlgorithmByVersionMap.keySet())
        );
    }
}
