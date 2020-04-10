package org.diplomatiq.diplomatiqbackend.exceptions.api;

import org.diplomatiq.diplomatiqbackend.exceptions.ApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;

public class UnauthorizedException extends ApiException {
    public UnauthorizedException() {
        super("Unauthorized", ApiExceptionOrigin.CLIENT, null, null);
    }
}
