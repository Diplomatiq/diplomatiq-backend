package org.diplomatiq.diplomatiqbackend.exceptions;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpStatus;

@JsonAutoDetect(
    fieldVisibility = JsonAutoDetect.Visibility.NONE,
    setterVisibility = JsonAutoDetect.Visibility.NONE,
    getterVisibility = JsonAutoDetect.Visibility.NONE,
    isGetterVisibility = JsonAutoDetect.Visibility.NONE,
    creatorVisibility = JsonAutoDetect.Visibility.NONE
)
public abstract class DiplomatiqApiException extends RuntimeException {
    @JsonProperty
    private final String errorCode;

    private final ApiExceptionOrigin exceptionOrigin;

    private final HttpStatus httpStatusCode;

    @JsonProperty
    private final RetryInformation retryInformation;

    private final String message;

    private final Exception internalException;

    public DiplomatiqApiException(String errorCode, ApiExceptionOrigin exceptionOrigin, HttpStatus httpStatusCode,
                                  RetryInformation retryInformation, String message, Exception internalException) {
        this.errorCode = errorCode;
        this.exceptionOrigin = exceptionOrigin;
        this.httpStatusCode = httpStatusCode;
        this.retryInformation = retryInformation;
        this.message = message;
        this.internalException = internalException;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public ApiExceptionOrigin getExceptionOrigin() {
        return exceptionOrigin;
    }

    public RetryInformation getRetryInformation() {
        return retryInformation;
    }

    public HttpStatus getHttpStatusCode() {
        if (httpStatusCode != null) {
            return httpStatusCode;
        }

        switch (exceptionOrigin) {
            case CLIENT:
                return HttpStatus.BAD_REQUEST;

            case SERVER:
                return HttpStatus.INTERNAL_SERVER_ERROR;
        }

        return HttpStatus.INTERNAL_SERVER_ERROR;
    }

    public String getMessage() {
        return message;
    }

    public Exception getInternalException() {
        return internalException;
    }
}