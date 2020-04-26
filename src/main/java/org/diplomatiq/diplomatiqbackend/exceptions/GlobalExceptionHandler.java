package org.diplomatiq.diplomatiqbackend.exceptions;

import org.diplomatiq.diplomatiqbackend.exceptions.internal.*;
import org.springframework.beans.ConversionNotSupportedException;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler({ BadRequestException.class })
    public ResponseEntity<Object> handleBadRequestException(BadRequestException exception,
                                                            WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.BadRequest, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @ExceptionHandler({ ClockDiscrepancyException.class })
    public ResponseEntity<Object> handleClockDiscrepancyException(ClockDiscrepancyException exception,
                                                                  WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.ClockDiscrepancy, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @ExceptionHandler({ MethodNotAllowedException.class })
    public ResponseEntity<Object> handleMethodNotAllowedException(MethodNotAllowedException exception,
                                                                  WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.MethodNotAllowed, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @ExceptionHandler({ UnauthorizedException.class })
    public ResponseEntity<Object> handleUnauthorizedException(UnauthorizedException exception, WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.Unauthorized, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @ExceptionHandler({ AccessDeniedException.class })
    public ResponseEntity<Object> handleAccessDeniedException(AccessDeniedException exception, WebRequest request) {
        DiplomatiqApiError apiError = new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.Unauthorized,
            exception);
        return handleDiplomatiqApiError(apiError);
    }

    @ExceptionHandler({ Exception.class })
    public ResponseEntity<Object> handleUnknownException(Exception exception, WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.InternalServerError,
                exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException exception,
                                                                         HttpHeaders headers, HttpStatus status,
                                                                         WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.MethodNotAllowed, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException exception,
                                                                     HttpHeaders headers, HttpStatus status,
                                                                     WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.UnsupportedMediaType,
                exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotAcceptable(HttpMediaTypeNotAcceptableException exception,
                                                                      HttpHeaders headers, HttpStatus status,
                                                                      WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.NotAcceptable, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleMissingPathVariable(MissingPathVariableException exception,
                                                               HttpHeaders headers,
                                                               HttpStatus status, WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.BadRequest, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException exception,
                                                                          HttpHeaders headers, HttpStatus status,
                                                                          WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.BadRequest, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleServletRequestBindingException(ServletRequestBindingException exception,
                                                                          HttpHeaders headers, HttpStatus status,
                                                                          WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.BadRequest, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleConversionNotSupported(ConversionNotSupportedException exception,
                                                                  HttpHeaders headers, HttpStatus status,
                                                                  WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.InternalServerError,
                exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleTypeMismatch(TypeMismatchException exception, HttpHeaders headers,
                                                        HttpStatus status, WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.BadRequest, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException exception,
                                                                  HttpHeaders headers, HttpStatus status,
                                                                  WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.BadRequest, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotWritable(HttpMessageNotWritableException exception,
                                                                  HttpHeaders headers, HttpStatus status,
                                                                  WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.InternalServerError,
                exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException exception,
                                                                  HttpHeaders headers, HttpStatus status,
                                                                  WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.BadRequest, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(MissingServletRequestPartException exception,
                                                                     HttpHeaders headers, HttpStatus status,
                                                                     WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.BadRequest, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleBindException(BindException exception, HttpHeaders headers,
                                                         HttpStatus status,
                                                         WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.BadRequest, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException exception,
                                                                   HttpHeaders headers,
                                                                   HttpStatus status, WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.NotFound, exception);
        return handleDiplomatiqApiError(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleAsyncRequestTimeoutException(AsyncRequestTimeoutException exception,
                                                                        HttpHeaders headers, HttpStatus status,
                                                                        WebRequest request) {
        DiplomatiqApiError apiError =
            new DiplomatiqApiError(DiplomatiqApiError.DiplomatiqApiErrorCode.InternalServerError,
                exception);
        return handleDiplomatiqApiError(apiError);
    }

    protected ResponseEntity<Object> handleDiplomatiqApiError(DiplomatiqApiError apiError) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Content-Type", "application/json");
        return new ResponseEntity<>(apiError, httpHeaders, DiplomatiqApiError.DIPLOMATIQ_API_ERROR_STATUS_CODE);
    }
}
