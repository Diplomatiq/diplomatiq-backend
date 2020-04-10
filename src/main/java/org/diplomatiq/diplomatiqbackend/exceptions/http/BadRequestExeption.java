package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.ApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class BadRequestExeption extends ApiException {
    public BadRequestExeption() {
        super("BadRequest", ApiExceptionOrigin.CLIENT, HttpStatus.BAD_REQUEST, null);
    }
}
