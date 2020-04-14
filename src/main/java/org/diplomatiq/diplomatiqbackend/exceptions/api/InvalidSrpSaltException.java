package org.diplomatiq.diplomatiqbackend.exceptions.api;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.ApiExceptionOrigin;

public class InvalidSrpSaltException extends DiplomatiqApiException {
    public InvalidSrpSaltException() {
        super("InvalidSrpSalt", ApiExceptionOrigin.CLIENT, null, null, null, null);
    }

    public InvalidSrpSaltException(String message, Exception internalException) {
        super("InvalidSrpSalt", ApiExceptionOrigin.CLIENT, null, null, message, internalException);
    }
}
