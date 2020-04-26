package org.diplomatiq.diplomatiqbackend.access;

import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqAuthenticationScheme;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationDetails;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationToken;
import org.diplomatiq.diplomatiqbackend.methods.attributes.SessionAssuranceLevel;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

public class ControllerSecurityExpressions extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {
    private AuthenticationService authenticationService;
    private Object filterObject;
    private Object returnObject;

    public ControllerSecurityExpressions(Authentication authentication, AuthenticationService authenticationService) {
        super(authentication);
        this.authenticationService = authenticationService;
    }

    public boolean hasSessionAssuranceLevel(SessionAssuranceLevel requiredAssuranceLevel) {
        Authentication authentication = getAuthentication();
        if (!(authentication instanceof AuthenticationToken)) {
            return false;
        }

        AuthenticationToken authenticationToken = (AuthenticationToken)authentication;
        AuthenticationDetails authenticationDetails = authenticationToken.getCredentials();
        if (!authenticationDetails.diplomatiqAuthenticationScheme().equals(DiplomatiqAuthenticationScheme.SessionSignatureV1)) {
            return false;
        }

        String sessionId = authenticationDetails.getAuthenticationId();
        return authenticationService.hasSessionAssuranceLevel(sessionId, requiredAssuranceLevel);
    }

    @Override
    public void setFilterObject(Object o) {
        filterObject = o;
    }

    @Override
    public Object getFilterObject() {
        return filterObject;
    }

    @Override
    public void setReturnObject(Object o) {
        returnObject = o;
    }

    @Override
    public Object getReturnObject() {
        return returnObject;
    }

    @Override
    public Object getThis() {
        return this;
    }
}
