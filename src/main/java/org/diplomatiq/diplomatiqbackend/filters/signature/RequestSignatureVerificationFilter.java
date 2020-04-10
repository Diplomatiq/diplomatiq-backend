package org.diplomatiq.diplomatiqbackend.filters.signature;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public class RequestSignatureVerificationFilter extends GenericFilterBean {
    private RequestMatcher requiresSignatureVerificationRequestMatcher;

    public RequestSignatureVerificationFilter(RequestMatcher requestMatcher) {
        requiresSignatureVerificationRequestMatcher = requestMatcher;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        filterChain.doFilter(request, response);
    }
}
