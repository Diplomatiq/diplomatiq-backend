package org.diplomatiq.diplomatiqbackend.exceptions;

import org.diplomatiq.diplomatiqbackend.exceptions.http.*;
import org.springframework.beans.ConversionNotSupportedException;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
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

    @ExceptionHandler({ DiplomatiqApiException.class })
    protected ResponseEntity<Object> handleDiplomatiqApIException(DiplomatiqApiException ex, WebRequest request) {
        return handleExceptionInternal(ex, ex, new HttpHeaders(), ex.getHttpStatusCode(), request);
    }

    @ExceptionHandler({ Exception.class })
    protected ResponseEntity<Object> handleEverything(Exception ex, WebRequest request) {
        InternalServerErrorException internalServerErrorException = new InternalServerErrorException();
        return handleExceptionInternal(ex, internalServerErrorException, new HttpHeaders(),
            internalServerErrorException.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException ex,
                                                                         HttpHeaders headers, HttpStatus status,
                                                                         WebRequest request) {
        MethodNotAllowedException exception = new MethodNotAllowedException();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex,
                                                                     HttpHeaders headers, HttpStatus status,
                                                                     WebRequest request) {
        UnsupportedMediaTypeException exception = new UnsupportedMediaTypeException();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotAcceptable(HttpMediaTypeNotAcceptableException ex,
                                                                      HttpHeaders headers, HttpStatus status,
                                                                      WebRequest request) {
        NotAcceptableException exception = new NotAcceptableException();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleMissingPathVariable(MissingPathVariableException ex, HttpHeaders headers,
                                                               HttpStatus status, WebRequest request) {
        BadRequestExeption exception = new BadRequestExeption();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException ex,
                                                                          HttpHeaders headers, HttpStatus status,
                                                                          WebRequest request) {
        BadRequestExeption exception = new BadRequestExeption();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleServletRequestBindingException(ServletRequestBindingException ex,
                                                                          HttpHeaders headers, HttpStatus status,
                                                                          WebRequest request) {
        BadRequestExeption exception = new BadRequestExeption();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleConversionNotSupported(ConversionNotSupportedException ex,
                                                                  HttpHeaders headers, HttpStatus status,
                                                                  WebRequest request) {
        InternalServerErrorException exception = new InternalServerErrorException();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleTypeMismatch(TypeMismatchException ex, HttpHeaders headers,
                                                        HttpStatus status, WebRequest request) {
        BadRequestExeption exception = new BadRequestExeption();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
                                                                  HttpHeaders headers, HttpStatus status,
                                                                  WebRequest request) {
        InternalServerErrorException exception = new InternalServerErrorException();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotWritable(HttpMessageNotWritableException ex,
                                                                  HttpHeaders headers, HttpStatus status,
                                                                  WebRequest request) {
        InternalServerErrorException exception = new InternalServerErrorException();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers, HttpStatus status,
                                                                  WebRequest request) {
        BadRequestExeption exception = new BadRequestExeption();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(MissingServletRequestPartException ex,
                                                                     HttpHeaders headers, HttpStatus status,
                                                                     WebRequest request) {
        BadRequestExeption exception = new BadRequestExeption();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleBindException(BindException ex, HttpHeaders headers, HttpStatus status,
                                                         WebRequest request) {
        BadRequestExeption exception = new BadRequestExeption();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException ex, HttpHeaders headers,
                                                                   HttpStatus status, WebRequest request) {
        NotFoundException exception = new NotFoundException();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleAsyncRequestTimeoutException(AsyncRequestTimeoutException ex,
                                                                        HttpHeaders headers, HttpStatus status,
                                                                        WebRequest request) {
        InternalServerErrorException exception = new InternalServerErrorException();
        return handleExceptionInternal(ex, exception, headers, exception.getHttpStatusCode(), request);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers,
                                                             HttpStatus status, WebRequest request) {
        headers.addIfAbsent("Content-Type", "application/json");
        return new ResponseEntity<>(body, headers, status);
    }

}
