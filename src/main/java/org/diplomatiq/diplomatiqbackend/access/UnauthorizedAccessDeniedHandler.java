package org.diplomatiq.diplomatiqbackend.access;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.exceptions.GlobalExceptionHandler;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class UnauthorizedAccessDeniedHandler implements AccessDeniedHandler {
    private GlobalExceptionHandler globalExceptionHandler;
    private ObjectMapper objectMapper;

    public UnauthorizedAccessDeniedHandler(GlobalExceptionHandler globalExceptionHandler, ObjectMapper objectMapper) {
        this.globalExceptionHandler = globalExceptionHandler;
        this.objectMapper = objectMapper;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException exception) throws IOException {
        ResponseEntity<Object> responseEntity = globalExceptionHandler.handleAccessDeniedException(exception,
            new ServletWebRequest(request));

        response.setStatus(responseEntity.getStatusCodeValue());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        for (Map.Entry<String, List<String>> headerEntry : responseEntity.getHeaders().entrySet()) {
            String headerName = headerEntry.getKey();
            List<String> headerValues = headerEntry.getValue();

            for (String headerValue : headerValues) {
                response.setHeader(headerName, headerValue);
            }
        }

        Object responseBody = Optional.ofNullable(responseEntity.getBody()).orElse(new Object());
        objectMapper.writeValue(response.getWriter(), responseBody);
    }
}
