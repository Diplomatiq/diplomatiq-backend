package org.diplomatiq.diplomatiqbackend.filters.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.exceptions.api.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.filters.RequestMatchingGenericFilterBean;
import org.diplomatiq.diplomatiqbackend.methods.entities.UserIdentity;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SessionAuthenticationFilter extends RequestMatchingGenericFilterBean {
    private static final String ENCRYPTED_SESSION_ID_KEY = "EncryptedSessionId";
    private static final String DEVICE_ID_KEY = "DeviceId";

    private AuthenticationService authenticationService;
    private ObjectMapper objectMapper;

    public SessionAuthenticationFilter(RequestMatcher requestMatcher, AuthenticationService authenticationService,
                                       ObjectMapper objectMapper) {
        super(requestMatcher);
        this.authenticationService = authenticationService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void doFilterIfRequestMatches(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        try {
            SessionAuthenticationToken authenticationResult = attemptAuthentication(request);
            SecurityContextHolder.getContext().setAuthentication(authenticationResult);
            chain.doFilter(servletRequest, servletResponse);
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            objectMapper.writeValue(response.getWriter(), new UnauthorizedException());
        }
    }

    public SessionAuthenticationToken attemptAuthentication(HttpServletRequest httpServletRequest) throws AuthenticationException {
        String encryptedSessionId = httpServletRequest.getHeader(ENCRYPTED_SESSION_ID_KEY);
        String deviceId = httpServletRequest.getHeader(DEVICE_ID_KEY);
        String sessionId = authenticationService.validateAndDecryptEncryptedSessionId(encryptedSessionId,
            deviceId);
        UserIdentity userIdentity = authenticationService.getUserBySessionId(sessionId);
        return new SessionAuthenticationToken(userIdentity, sessionId);
    }
}
