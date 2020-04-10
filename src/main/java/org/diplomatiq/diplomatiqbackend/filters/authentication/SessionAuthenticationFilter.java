package org.diplomatiq.diplomatiqbackend.filters.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.exceptions.api.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.methods.entities.UserIdentity;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SessionAuthenticationFilter extends GenericFilterBean {
    private static final String ENCRYPTED_SESSION_ID_KEY = "EncryptedSessionId";
    private static final String DEVICE_ID_KEY = "DeviceId";

    private RequestMatcher requiresAuthenticationRequestMatcher;
    private AuthenticationService authenticationService;
    private ObjectMapper objectMapper;

    public SessionAuthenticationFilter(RequestMatcher requestMatcher, AuthenticationService authenticationService,
                                       ObjectMapper objectMapper) {
        requiresAuthenticationRequestMatcher = requestMatcher;
        this.authenticationService = authenticationService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        if (!requiresAuthentication(request)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            SessionAuthenticationToken authenticationResult = attemptAuthentication(request);
            SecurityContextHolder.getContext().setAuthentication(authenticationResult);
            chain.doFilter(request, response);
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            objectMapper.writeValue(response.getWriter(), new UnauthorizedException());
        }
    }

    private boolean requiresAuthentication(HttpServletRequest request) {
        return requiresAuthenticationRequestMatcher.matches(request);
    }

    public SessionAuthenticationToken attemptAuthentication(HttpServletRequest httpServletRequest) throws AuthenticationException {
        String encryptedSessionId = httpServletRequest.getHeader(ENCRYPTED_SESSION_ID_KEY);
        String deviceId = httpServletRequest.getHeader(DEVICE_ID_KEY);
        String sessionId = authenticationService.validateAndDecryptEncryptedSessionId(encryptedSessionId,
            deviceId);
        UserIdentity userIdentity = authenticationService.lookupUserBySessionId(sessionId);
        return new SessionAuthenticationToken(userIdentity, sessionId);
    }
}
