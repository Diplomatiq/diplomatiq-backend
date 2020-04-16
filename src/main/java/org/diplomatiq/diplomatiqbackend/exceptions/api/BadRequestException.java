package org.diplomatiq.diplomatiqbackend.exceptions.api;

import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;

public class BadRequestException extends DiplomatiqApiException {
    public BadRequestException() {
        super("BadRequestExeption", ApiExceptionOrigin.CLIENT, null, null, null, null);
    }

    public BadRequestException(String message, Exception internalException) {
        super("BadRequestExeption", ApiExceptionOrigin.CLIENT, null, null, message, internalException);
    }
}
