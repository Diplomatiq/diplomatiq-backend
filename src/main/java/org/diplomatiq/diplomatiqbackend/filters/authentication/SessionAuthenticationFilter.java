package org.diplomatiq.diplomatiqbackend.filters.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.exceptions.GlobalExceptionHandler;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.filters.JsonResponseWritingFilter;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SessionAuthenticationFilter extends JsonResponseWritingFilter {
    private static final String ENCRYPTED_SESSION_ID_KEY = "EncryptedSessionId";
    private static final String DEVICE_ID_KEY = "DeviceId";

    private AuthenticationService authenticationService;
    private GlobalExceptionHandler globalExceptionHandler;

    public SessionAuthenticationFilter(RequestMatcher requestMatcher, ObjectMapper objectMapper,
                                       AuthenticationService authenticationService,
                                       GlobalExceptionHandler globalExceptionHandler) {
        super(requestMatcher, objectMapper);
        this.authenticationService = authenticationService;
        this.globalExceptionHandler = globalExceptionHandler;
    }

    @Override
    public void doFilterIfRequestMatches(ServletRequest servletRequest, ServletResponse servletResponse,
                                         FilterChain chain) throws IOException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        try {
            SessionAuthenticationToken authenticationResult = attemptAuthentication(request);
            SecurityContextHolder.getContext().setAuthentication(authenticationResult);
            chain.doFilter(servletRequest, servletResponse);
        } catch (UnauthorizedException ex) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleUnauthorizedException(ex,
                new ServletWebRequest(request));
            writeJsonResponse(response, responseEntity);
        } catch (Exception ex) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleUnknownException(ex,
                new ServletWebRequest(request));
            writeJsonResponse(response, responseEntity);
        }
    }

    public SessionAuthenticationToken attemptAuthentication(HttpServletRequest httpServletRequest) throws AuthenticationException {
        String encryptedSessionId = httpServletRequest.getHeader(ENCRYPTED_SESSION_ID_KEY);
        String deviceId = httpServletRequest.getHeader(DEVICE_ID_KEY);

        String sessionId;

        try {
            sessionId = authenticationService.validateAndDecryptEncryptedSessionId(encryptedSessionId, deviceId);
        } catch (Exception ex) {
            throw new UnauthorizedException("Could not get sessionId.", ex);
        }

        UserIdentity userIdentity;

        try {
            userIdentity = authenticationService.getUserBySessionId(sessionId);
        } catch (Exception ex) {
            throw new UnauthorizedException("Could not get userIdentity.", ex);
        }

        return new SessionAuthenticationToken(userIdentity, sessionId);
    }
}
