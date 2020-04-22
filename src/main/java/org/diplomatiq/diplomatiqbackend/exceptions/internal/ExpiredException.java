package org.diplomatiq.diplomatiqbackend.exceptions.internal;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqException;

public class ExpiredException extends DiplomatiqException {
    public ExpiredException(String message) {
        super(message);
    }

    public ExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
