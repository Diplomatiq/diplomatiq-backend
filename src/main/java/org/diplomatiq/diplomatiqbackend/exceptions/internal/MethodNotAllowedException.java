package org.diplomatiq.diplomatiqbackend.exceptions.internal;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqException;

public class MethodNotAllowedException extends DiplomatiqException {
    public MethodNotAllowedException(String message) {
        super(message);
    }

    public MethodNotAllowedException(String message, Throwable cause) {
        super(message, cause);
    }
}
