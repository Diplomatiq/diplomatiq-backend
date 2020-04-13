package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class NotFoundException extends DiplomatiqApiException {
    public NotFoundException() {
        super("NotFound", ApiExceptionOrigin.CLIENT, HttpStatus.NOT_FOUND, null, null, null);
    }

    public NotFoundException(String message, Exception internalException) {
        super("NotFound", ApiExceptionOrigin.CLIENT, HttpStatus.NOT_FOUND, null, message, internalException);
    }
}
