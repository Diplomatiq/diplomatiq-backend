package org.diplomatiq.diplomatiqbackend.filters;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public abstract class RequestMatchingGenericFilterBean extends GenericFilterBean {
    protected RequestMatcher requestMatcher;

    public RequestMatchingGenericFilterBean(RequestMatcher requestMatcher) {
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
