package org.diplomatiq.diplomatiqbackend.filters.signature;

import org.diplomatiq.diplomatiqbackend.filters.RequestMatchingGenericFilterBean;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public class RequestSignatureVerificationFilter extends RequestMatchingGenericFilterBean {

    public RequestSignatureVerificationFilter(RequestMatcher requestMatcher) {
        super(requestMatcher);
    }

    @Override
    public void doFilterIfRequestMatches(ServletRequest servletRequest, ServletResponse servletResponse,
                                         FilterChain filterChain) throws IOException, ServletException {
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
