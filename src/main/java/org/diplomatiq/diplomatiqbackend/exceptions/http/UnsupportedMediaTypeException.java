package org.diplomatiq.diplomatiqbackend.exceptions.http;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.springframework.http.HttpStatus;

public class UnsupportedMediaTypeException extends DiplomatiqApiException {
    public UnsupportedMediaTypeException() {
        super("UnsupportedMediaType", ApiExceptionOrigin.CLIENT, HttpStatus.UNSUPPORTED_MEDIA_TYPE, null, null, null);
    }

    public UnsupportedMediaTypeException(String message, Exception internalException) {
        super("UnsupportedMediaType", ApiExceptionOrigin.CLIENT, HttpStatus.UNSUPPORTED_MEDIA_TYPE, null, message,
            internalException);
    }
}
