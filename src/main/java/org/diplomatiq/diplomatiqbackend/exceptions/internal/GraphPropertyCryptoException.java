package org.diplomatiq.diplomatiqbackend.exceptions.internal;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqException;

public class GraphPropertyCryptoException extends DiplomatiqException {
    public GraphPropertyCryptoException(String message) {
        super(message);
    }

    public GraphPropertyCryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
