package org.diplomatiq.diplomatiqbackend.exceptions.api;

import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;
import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;

public class InvalidSrpVerifierException extends DiplomatiqApiException {
    public InvalidSrpVerifierException() {
        super("InvalidSrpVerifier", ApiExceptionOrigin.CLIENT, null, null, null, null);
    }

    public InvalidSrpVerifierException(String message, Exception internalException) {
        super("InvalidSrpVerifier", ApiExceptionOrigin.CLIENT, null, null, message, internalException);
    }
}
