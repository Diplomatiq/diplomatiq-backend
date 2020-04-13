package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class InternalServerErrorException extends DiplomatiqApiException {
    public InternalServerErrorException() {
        super("InternalServerError", ApiExceptionOrigin.SERVER, HttpStatus.INTERNAL_SERVER_ERROR, null, null, null);
    }

    public InternalServerErrorException(String message, Exception internalException) {
        super("InternalServerError", ApiExceptionOrigin.SERVER, HttpStatus.INTERNAL_SERVER_ERROR, null, message,
            internalException);
    }
}
