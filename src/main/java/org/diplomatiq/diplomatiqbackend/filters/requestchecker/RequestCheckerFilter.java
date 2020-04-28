package org.diplomatiq.diplomatiqbackend.filters.requestchecker;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.exceptions.GlobalExceptionHandler;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.BadRequestException;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.MethodNotAllowedException;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqHeaders;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqMethods;
import org.diplomatiq.diplomatiqbackend.filters.RequestMatchingFilter;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RequestCheckerFilter extends RequestMatchingFilter {
    private GlobalExceptionHandler globalExceptionHandler;

    public RequestCheckerFilter(ObjectMapper objectMapper, RequestMatcher requestMatcher,
                                GlobalExceptionHandler globalExceptionHandler) {
        super(objectMapper, requestMatcher);
        this.globalExceptionHandler = globalExceptionHandler;
    }

    @Override
    public void doFilterIfRequestMatches(ServletRequest servletRequest, ServletResponse servletResponse,
                                         FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        String requestMethod = request.getMethod().toUpperCase();
        String clientIdHeader = request.getHeader(DiplomatiqHeaders.KnownHeader.ClientId.name());
        String instantHeader = request.getHeader(DiplomatiqHeaders.KnownHeader.Instant.name());

        if (!DiplomatiqMethods.AllowedMethods.contains(requestMethod)) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleMethodNotAllowedException(
                new MethodNotAllowedException(requestMethod),
                new ServletWebRequest(request)
            );
            writeJsonResponse(response, responseEntity);
            return;
        }

        if (clientIdHeader == null || clientIdHeader.equals("")) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleBadRequestException(
                new BadRequestException("ClientId header must not be null or empty."),
                new ServletWebRequest(request)
            );
            writeJsonResponse(response, responseEntity);
            return;
        }

        if (instantHeader == null || instantHeader.equals("")) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleBadRequestException(
                new BadRequestException("Instant header must not be null or empty."),
                new ServletWebRequest(request)
            );
            writeJsonResponse(response, responseEntity);
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
