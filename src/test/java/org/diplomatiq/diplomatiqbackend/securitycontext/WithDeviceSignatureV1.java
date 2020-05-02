package org.diplomatiq.diplomatiqbackend.securitycontext;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithDeviceSignatureV1SecurityContextFactory.class)
public @interface WithDeviceSignatureV1 {
}
