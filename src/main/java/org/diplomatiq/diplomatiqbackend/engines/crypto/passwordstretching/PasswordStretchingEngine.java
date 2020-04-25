package org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching;

import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Map;

@Component
public class PasswordStretchingEngine {
    private static final Map<Integer, PasswordStretchingAlgorithm> passwordStretchingAlgorithmByVersionMap =
        Collections.unmodifiableMap(
            Map.ofEntries(
                Map.entry(1, PasswordStretchingAlgorithm.Argon2_v1)
            )
        );

    public PasswordStretchingAlgorithm getLatestAlgorithm() {
        return passwordStretchingAlgorithmByVersionMap.get(
            Collections.max(passwordStretchingAlgorithmByVersionMap.keySet())
        );
    }
}
