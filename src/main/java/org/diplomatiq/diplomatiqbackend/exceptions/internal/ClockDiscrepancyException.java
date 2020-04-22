package org.diplomatiq.diplomatiqbackend.exceptions.internal;

import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqException;

public class ClockDiscrepancyException extends DiplomatiqException {
    public ClockDiscrepancyException(String message) {
        super(message);
    }

    public ClockDiscrepancyException(String message, Throwable cause) {
        super(message, cause);
    }
}
