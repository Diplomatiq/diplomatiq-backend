package org.diplomatiq.diplomatiqbackend.utils.crypto.passwordstretching;

import org.bouncycastle.crypto.Digest;

public abstract class AbstractPasswordStretchingAlgorithmImpl implements Digest {

    public abstract String getAlgorithmBaseName();
    public abstract int getAlgorithmVersion();

    @Override
    public final String getAlgorithmName() {
        return String.format("%s_v%d", getAlgorithmBaseName(), getAlgorithmVersion());
    }

}
