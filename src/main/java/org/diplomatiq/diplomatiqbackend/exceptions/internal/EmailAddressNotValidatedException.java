package org.diplomatiq.diplomatiqbackend.exceptions.internal;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqException;

public class EmailAddressNotValidatedException extends DiplomatiqException {
    public EmailAddressNotValidatedException(String message) {
        super(message);
    }

    public EmailAddressNotValidatedException(String message, Throwable cause) {
        super(message, cause);
    }
}
