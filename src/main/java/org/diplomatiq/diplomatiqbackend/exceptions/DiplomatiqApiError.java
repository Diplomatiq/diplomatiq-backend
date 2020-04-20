package org.diplomatiq.diplomatiqbackend.exceptions;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.http.HttpStatus;

import javax.validation.constraints.NotNull;
import java.util.Optional;

public final class DiplomatiqApiError {
    public static final HttpStatus DIPLOMATIQ_API_ERROR_STATUS_CODE = HttpStatus.BAD_REQUEST;

    public enum DiplomatiqApiErrorCode {
        BadRequest,
        InternalServerError,
        MethodNotAllowed,
        NotAcceptable,
        NotFound,
        Unauthorized,
        UnsupportedMediaType,
    }

    @Schema(
        description = "The identifier of the error for client reactions",
        example = "BadRequest"
    )
    @NotNull
    private final DiplomatiqApiError.DiplomatiqApiErrorCode errorCode;

    @Schema(description = "Optional retry information for the client")
    private final RetryInformation retryInformation;

    @JsonIgnore
    private final Throwable cause;

    public DiplomatiqApiError(DiplomatiqApiErrorCode errorCode, Throwable cause, RetryInformation retryInformation) {
        this.errorCode = Optional.ofNullable(errorCode).orElse(DiplomatiqApiErrorCode.InternalServerError);
        this.cause = cause;
        this.retryInformation = retryInformation;
    }

    public DiplomatiqApiErrorCode getErrorCode() {
        return errorCode;
    }

    public Throwable getCause() {
        return cause;
    }

    public RetryInformation getRetryInformation() {
        return retryInformation;
    }
}