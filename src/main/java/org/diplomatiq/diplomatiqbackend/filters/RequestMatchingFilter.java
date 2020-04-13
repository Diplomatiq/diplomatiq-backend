package org.diplomatiq.diplomatiqbackend.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public abstract class RequestMatchingFilter extends JsonErrorResponseWritingExceptionLoggingFilter {

    protected RequestMatcher requestMatcher;
    protected ObjectMapper objectMapper;

    public RequestMatchingFilter(RequestMatcher requestMatcher, ObjectMapper objectMapper) {
        super(objectMapper);
        this.requestMatcher = requestMatcher;
    }

    protected boolean requestMatches(HttpServletRequest request) {
        return requestMatcher.matches(request);
    }

    @Override
    public final void doFilter(ServletRequest request, ServletResponse response,
                               FilterChain chain) throws IOException, ServletException {
        if (requestMatches((HttpServletRequest)request)) {
            doFilterIfRequestMatches(request, response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    public abstract void doFilterIfRequestMatches(ServletRequest servletRequest, ServletResponse servletResponse,
                                                  FilterChain filterChain) throws IOException, ServletException;
}
