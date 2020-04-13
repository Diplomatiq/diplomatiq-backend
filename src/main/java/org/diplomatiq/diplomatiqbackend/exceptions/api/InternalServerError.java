package org.diplomatiq.diplomatiqbackend.exceptions.api;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;

public class InternalServerError extends DiplomatiqApiException {
    public InternalServerError() {
        super("InternalServerError", ApiExceptionOrigin.SERVER, null, null, null, null);
    }

    public InternalServerError(String message, Exception internalException) {
        super("InternalServerError", ApiExceptionOrigin.SERVER, null, null, message, internalException);
    }
}
