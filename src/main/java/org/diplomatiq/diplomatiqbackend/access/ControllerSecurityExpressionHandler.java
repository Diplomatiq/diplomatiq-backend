package org.diplomatiq.diplomatiqbackend.access;

import org.aopalliance.intercept.MethodInvocation;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

public class ControllerSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private AuthenticationService authenticationService;

    public ControllerSecurityExpressionHandler(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Override
    protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
                                                                              MethodInvocation invocation) {
        ControllerSecurityExpressions root =
            new ControllerSecurityExpressions(authentication, authenticationService);
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(trustResolver);
        root.setRoleHierarchy(getRoleHierarchy());
        return root;
    }
}
