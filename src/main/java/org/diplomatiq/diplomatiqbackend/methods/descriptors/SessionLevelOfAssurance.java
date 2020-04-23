package org.diplomatiq.diplomatiqbackend.methods.descriptors;

public enum SessionLevelOfAssurance {
    RegularSession(1),
    PasswordElevatedSession(2),
    MultiFactorElevatedSession(3);

    private final int numericAssuranceLevel;

    SessionLevelOfAssurance(int numericAssuranceLevel) {
        this.numericAssuranceLevel = numericAssuranceLevel;
    }

    public int getNumericAssuranceLevel() {
        return numericAssuranceLevel;
    }
}
