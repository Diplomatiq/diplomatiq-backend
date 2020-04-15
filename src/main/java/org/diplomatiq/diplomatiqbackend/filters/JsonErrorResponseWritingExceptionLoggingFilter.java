package org.diplomatiq.diplomatiqbackend.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public abstract class JsonErrorResponseWritingExceptionLoggingFilter extends GenericFilterBean {
    private final Logger logger = LoggerFactory.getLogger(JsonErrorResponseWritingExceptionLoggingFilter.class);

    private ObjectMapper objectMapper;

    public JsonErrorResponseWritingExceptionLoggingFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void writeJsonErrorResponse(HttpServletResponse response, DiplomatiqApiException exception) throws IOException {
        response.setStatus(exception.getHttpStatusCode().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        logger.debug(exception.getMessage(), exception.getInternalException());
        objectMapper.writeValue(response.getWriter(), exception);
    }

    public void writeJsonErrorResponse(HttpServletResponse response, HttpStatus httpStatus, Exception exception) throws IOException {
        response.setStatus(httpStatus.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        logger.debug(exception.getMessage(), exception);
        objectMapper.writeValue(response.getWriter(), exception);
    }
}
