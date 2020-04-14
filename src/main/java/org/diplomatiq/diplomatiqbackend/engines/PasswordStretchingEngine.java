package org.diplomatiq.diplomatiqbackend.engines;

import org.diplomatiq.diplomatiqbackend.utils.crypto.passwordstretching.AbstractPasswordStretchingAlgorithmImpl;
import org.diplomatiq.diplomatiqbackend.utils.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.utils.crypto.passwordstretching.impl.argon2.Argon2;
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

    public AbstractPasswordStretchingAlgorithmImpl getImplByAlgorithm(PasswordStretchingAlgorithm algorithm) {
        switch (algorithm) {
            case Argon2_v1:
                return Argon2.v1();
            default:
                throw new UnsupportedOperationException(String.format("No such algorithm found: %s.",
                    algorithm));
        }
    }
}
