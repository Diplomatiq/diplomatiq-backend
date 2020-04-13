package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class BadRequestExeption extends DiplomatiqApiException {
    public BadRequestExeption() {
        super("BadRequest", ApiExceptionOrigin.CLIENT, HttpStatus.BAD_REQUEST, null, null, null);
    }

    public BadRequestExeption(String message, Exception internalException) {
        super("BadRequest", ApiExceptionOrigin.CLIENT, HttpStatus.BAD_REQUEST, null, message, internalException);
    }
}
