package org.diplomatiq.diplomatiqbackend.filters.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.exceptions.GlobalExceptionHandler;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.BadRequestException;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqAuthenticationScheme;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqHeaders;
import org.diplomatiq.diplomatiqbackend.filters.RequestMatchingFilter;
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

public class AuthenticationFilter extends RequestMatchingFilter {
    private AuthenticationService authenticationService;
    private GlobalExceptionHandler globalExceptionHandler;

    public AuthenticationFilter(ObjectMapper objectMapper, RequestMatcher requestMatcher,
                                AuthenticationService authenticationService,
                                GlobalExceptionHandler globalExceptionHandler) {
        super(objectMapper, requestMatcher);
        this.authenticationService = authenticationService;
        this.globalExceptionHandler = globalExceptionHandler;
    }

    @Override
    public void doFilterIfRequestMatches(ServletRequest servletRequest, ServletResponse servletResponse,
                                         FilterChain chain) throws IOException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        try {
            AuthenticationToken authenticationResult = attemptAuthentication(request);
            SecurityContextHolder.getContext().setAuthentication(authenticationResult);
            chain.doFilter(servletRequest, servletResponse);
        } catch (BadRequestException ex) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleBadRequestException(ex,
                new ServletWebRequest(request));
            writeJsonResponse(response, responseEntity);
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

    public AuthenticationToken attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || authorizationHeader.equals("")) {
            throw new BadRequestException("Authorization header must not be null or empty.");
        }

        String[] authorizationHeaderSplit = authorizationHeader.split(" ");
        String authenticationSchemeString = authorizationHeaderSplit[0];

        DiplomatiqAuthenticationScheme authenticationScheme;
        try {
            authenticationScheme = DiplomatiqAuthenticationScheme.valueOf(authenticationSchemeString);
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Unknown authentication scheme.", ex);
        }

        String authenticationSessionId =
            request.getHeader(DiplomatiqHeaders.KnownHeader.AuthenticationSessionId.name());
        String deviceId = request.getHeader(DiplomatiqHeaders.KnownHeader.DeviceId.name());
        String sessionId = request.getHeader(DiplomatiqHeaders.KnownHeader.SessionId.name());

        String authenticationId;
        UserIdentity userIdentity;
        switch (authenticationScheme) {
            case AuthenticationSessionSignatureV1:
                userIdentity = authenticateWithAuthenticationSessionSignatureV1(authenticationSessionId);
                authenticationId = authenticationSessionId;
                break;

            case DeviceSignatureV1:
                userIdentity = authenticateWithDeviceSignatureV1(deviceId);
                authenticationId = deviceId;
                break;

            case SessionSignatureV1:
                userIdentity = authenticateWithSessionSignatureV1(deviceId, sessionId);
                authenticationId = sessionId;
                break;

            default:
                throw new BadRequestException("Unknown authentication scheme.");
        }

        if (!userIdentity.isEmailValidated()) {
            throw new UnauthorizedException("Email address is not validated.");
        }

        return new AuthenticationToken(userIdentity, new AuthenticationDetails(authenticationScheme, authenticationId));
    }

    public UserIdentity authenticateWithAuthenticationSessionSignatureV1(String authenticationSessionId) {
        try {
            return authenticationService.verifyAuthenticationSessionCredentials(authenticationSessionId);
        } catch (Exception ex) {
            throw new UnauthorizedException("Authentication session credentials could not be verified.", ex);
        }
    }

    public UserIdentity authenticateWithDeviceSignatureV1(String deviceId) {
        try {
            return authenticationService.verifyDeviceCredentials(deviceId);
        } catch (Exception ex) {
            throw new UnauthorizedException("Device credentials could not be verified.", ex);
        }
    }

    public UserIdentity authenticateWithSessionSignatureV1(String deviceId, String sessionId) {
        try {
            return authenticationService.verifySessionCredentials(deviceId, sessionId);
        } catch (Exception ex) {
            throw new UnauthorizedException("Session credentials could not be verified.", ex);
        }
    }
}
