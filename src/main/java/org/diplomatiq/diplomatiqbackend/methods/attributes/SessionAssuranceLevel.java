package org.diplomatiq.diplomatiqbackend.methods.attributes;

public enum SessionAssuranceLevel {
    RegularSession(1),
    PasswordElevatedSession(2),
    MultiFactorElevatedSession(3);

    private final int numericAssuranceLevel;

    SessionAssuranceLevel(int numericAssuranceLevel) {
        this.numericAssuranceLevel = numericAssuranceLevel;
    }

    public int getNumericAssuranceLevel() {
        return numericAssuranceLevel;
    }
}
