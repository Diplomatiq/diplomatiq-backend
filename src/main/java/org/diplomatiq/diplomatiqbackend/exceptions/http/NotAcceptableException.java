package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class NotAcceptableException extends DiplomatiqApiException {
    public NotAcceptableException() {
        super("NotAcceptable", ApiExceptionOrigin.CLIENT, HttpStatus.NOT_ACCEPTABLE, null, null, null);
    }

    public NotAcceptableException(String message, Exception internalException) {
        super("NotAcceptable", ApiExceptionOrigin.CLIENT, HttpStatus.NOT_ACCEPTABLE, null, message, internalException);
    }
}
