package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.ApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class MethodNotAllowedException extends ApiException {
    public MethodNotAllowedException() {
        super("MethodNotAllowed", ApiExceptionOrigin.CLIENT, HttpStatus.METHOD_NOT_ALLOWED, null);
    }
}
