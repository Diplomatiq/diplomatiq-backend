package org.diplomatiq.diplomatiqbackend.exceptions;

public abstract class ApiException {
    private final String errorCode;
    private final RetryInformation retryInformation;

    protected ApiException(String errorCode, RetryInformation retryInformation) {
        this.errorCode = errorCode;
        this.retryInformation = retryInformation;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public RetryInformation getRetryInformation() {
        return retryInformation;
    }
}
