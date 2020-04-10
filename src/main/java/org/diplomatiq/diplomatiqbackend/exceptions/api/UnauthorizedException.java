package org.diplomatiq.diplomatiqbackend.exceptions.api;

import org.diplomatiq.diplomatiqbackend.exceptions.ApiException;

public class UnauthorizedException extends ApiException {
    public UnauthorizedException() {
        super("Unauthorized", null);
    }
}
