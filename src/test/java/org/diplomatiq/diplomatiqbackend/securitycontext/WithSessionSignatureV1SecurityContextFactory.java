package org.diplomatiq.diplomatiqbackend.securitycontext;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqAuthenticationScheme;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationDetails;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationToken;
import org.diplomatiq.diplomatiqbackend.testutils.DummyData;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

public class WithSessionSignatureV1SecurityContextFactory implements WithSecurityContextFactory<WithSessionSignatureV1> {
    @Override
    public SecurityContext createSecurityContext(WithSessionSignatureV1 withSessionSignatureV1) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL,
            DummyData.USER_FIRST_NAME, DummyData.USER_LAST_NAME);
        userIdentity.setEmailValidated(true);

        AuthenticationDetails authenticationDetails =
            new AuthenticationDetails(DiplomatiqAuthenticationScheme.SessionSignatureV1, DummyData.SESSION_ID);

        AuthenticationToken authenticationToken = new AuthenticationToken(userIdentity, authenticationDetails);

        securityContext.setAuthentication(authenticationToken);
        return securityContext;
    }
}
