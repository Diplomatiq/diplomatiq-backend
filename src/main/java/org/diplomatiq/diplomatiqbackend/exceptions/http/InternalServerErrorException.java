package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.ApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class InternalServerErrorException extends ApiException {
    public InternalServerErrorException() {
        super("InternalServerError", ApiExceptionOrigin.SERVER, HttpStatus.INTERNAL_SERVER_ERROR, null);
    }
}
