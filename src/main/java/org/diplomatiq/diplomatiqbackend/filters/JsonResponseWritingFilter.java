package org.diplomatiq.diplomatiqbackend.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public abstract class JsonResponseWritingFilter extends GenericFilterBean {
    private ObjectMapper objectMapper;

    public JsonResponseWritingFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void writeJsonResponse(HttpServletResponse response, ResponseEntity<Object> responseEntity) throws IOException {
        response.setStatus(responseEntity.getStatusCodeValue());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

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
