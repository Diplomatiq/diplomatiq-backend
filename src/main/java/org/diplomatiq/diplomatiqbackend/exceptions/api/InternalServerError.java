package org.diplomatiq.diplomatiqbackend.exceptions.api;

import org.diplomatiq.diplomatiqbackend.exceptions.ApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;

public class InternalServerError extends ApiException {
    public InternalServerError() {
        super("InternalServerError", ApiExceptionOrigin.SERVER, null, null);
    }
}
