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

public class WithDeviceSignatureV1SecurityContextFactory implements WithSecurityContextFactory<WithDeviceSignatureV1> {
    @Override
    public SecurityContext createSecurityContext(WithDeviceSignatureV1 withDeviceSignatureV1) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

        UserIdentity userIdentity = UserIdentityHelper.create(DummyData.USER_EMAIL,
            DummyData.USER_FIRST_NAME, DummyData.USER_LAST_NAME);
        userIdentity.setEmailValidated(true);

        AuthenticationDetails authenticationDetails =
            new AuthenticationDetails(DiplomatiqAuthenticationScheme.DeviceSignatureV1,
                DummyData.DEVICE_ID);

        AuthenticationToken authenticationToken = new AuthenticationToken(userIdentity, authenticationDetails);

        securityContext.setAuthentication(authenticationToken);
        return securityContext;
    }
}
