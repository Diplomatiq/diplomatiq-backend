package org.diplomatiq.diplomatiqbackend.exceptions.api;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;

public class UnauthorizedException extends DiplomatiqApiException {
    public UnauthorizedException() {
        super("Unauthorized", ApiExceptionOrigin.CLIENT, null, null, null, null);
    }

    public UnauthorizedException(String message, Exception internalException) {
        super("Unauthorized", ApiExceptionOrigin.CLIENT, null, null, message, internalException);
    }
}
