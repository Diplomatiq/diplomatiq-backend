package org.diplomatiq.diplomatiqbackend.exceptions.api;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;

public class InternalServerErrorException extends DiplomatiqApiException {
    public InternalServerErrorException() {
        super("InternalServerError", ApiExceptionOrigin.SERVER, null, null, null, null);
    }

    public InternalServerErrorException(String message, Exception internalException) {
        super("InternalServerError", ApiExceptionOrigin.SERVER, null, null, message, internalException);
    }
}
