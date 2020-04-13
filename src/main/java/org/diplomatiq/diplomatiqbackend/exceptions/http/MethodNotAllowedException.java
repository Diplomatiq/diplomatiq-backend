package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class MethodNotAllowedException extends DiplomatiqApiException {
    public MethodNotAllowedException() {
        super("MethodNotAllowed", ApiExceptionOrigin.CLIENT, HttpStatus.METHOD_NOT_ALLOWED, null, null, null);
    }

    public MethodNotAllowedException(String message, Exception internalException) {
        super("MethodNotAllowed", ApiExceptionOrigin.CLIENT, HttpStatus.METHOD_NOT_ALLOWED, null, message,
            internalException);
    }
}
