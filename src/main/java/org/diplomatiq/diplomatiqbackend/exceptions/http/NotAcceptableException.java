package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.ApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class NotAcceptableException extends ApiException {
    public NotAcceptableException() {
        super("NotAcceptable", ApiExceptionOrigin.CLIENT, HttpStatus.NOT_ACCEPTABLE, null);
    }
}
