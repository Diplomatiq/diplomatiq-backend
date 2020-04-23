package org.diplomatiq.diplomatiqbackend.methods.descriptors;

public enum SessionLevelOfAssurance {
    RegularSession(1),
    PasswordElevatedSession(2),
    MultiFactorElevatedSession(3);

    public final int assuranceLevel;

    private SessionLevelOfAssurance(int assuranceLevel) {
        this.assuranceLevel = assuranceLevel;
    }
}
