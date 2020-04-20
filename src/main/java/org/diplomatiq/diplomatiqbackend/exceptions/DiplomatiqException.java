package org.diplomatiq.diplomatiqbackend.exceptions;

public abstract class DiplomatiqException extends RuntimeException {
    public DiplomatiqException(String message) {
        super(message);
    }

    public DiplomatiqException(String message, Throwable cause) {
        super(message, cause);
    }
}
