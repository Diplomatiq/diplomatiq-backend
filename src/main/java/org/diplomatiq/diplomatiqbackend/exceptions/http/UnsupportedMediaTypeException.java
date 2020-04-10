package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.ApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class UnsupportedMediaTypeException extends ApiException {
    public UnsupportedMediaTypeException() {
        super("UnsupportedMediaType", ApiExceptionOrigin.CLIENT, HttpStatus.UNSUPPORTED_MEDIA_TYPE, null);
    }
}
