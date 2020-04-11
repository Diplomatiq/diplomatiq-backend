package org.diplomatiq.diplomatiqbackend.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.filters.authentication.SessionAuthenticationFilter;
import org.diplomatiq.diplomatiqbackend.filters.signature.RequestSignatureVerificationFilter;
import org.diplomatiq.diplomatiqbackend.methods.controllers.UnauthenticatedMethods;
import org.diplomatiq.diplomatiqbackend.methods.utils.ControllerPathLister;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;

@EnableWebSecurity
public class SecurityConfiguration {

    @Configuration
    @Order(1)
    public static class OpenApiSecurityConfiguration extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/openapi-documentation/**");

            http.headers(headers -> {
                headers.cacheControl();
                headers.frameOptions().deny();
                headers.httpStrictTransportSecurity()
                    .maxAgeInSeconds(63072000)
                    .includeSubDomains(true)
                    .preload(true);
                headers.xssProtection().block(true);
                headers.contentSecurityPolicy(csp ->
                    csp.policyDirectives(
                        "default-src 'none'; " +
                            "base-uri 'self'; " +
                            "form-action 'none'; " +
                            "frame-ancestors 'none'; " +
                            "img-src 'self' data:; " +
                            "script-src 'self' 'unsafe-inline'; " +
                            "style-src 'self' 'unsafe-inline'; " +
                            "font-src 'self'; " +
                            "connect-src 'self';"
                    )
                );
                headers.referrerPolicy().policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER);
                headers.featurePolicy(
                    "geolocation 'none'; " +
                        "midi 'none'; " +
                        "notifications 'none'; " +
                        "push 'none'; " +
                        "sync-xhr 'none'; " +
                        "microphone 'none'; " +
                        "camera 'none'; " +
                        "magnetometer 'none'; " +
                        "gyroscope 'none'; " +
                        "speaker 'none'; " +
                        "vibrate 'none'; " +
                        "fullscreen 'none'; " +
                        "payment 'none';"
                );
            });

            http.cors(cors -> {
                CorsConfigurationSource openApiCorsConfigurationSource = httpServletRequest -> {
                    CorsConfiguration defaultCorsConfiguration = new CorsConfiguration();
                    defaultCorsConfiguration.setAllowedOrigins(Arrays.asList("*"));
                    defaultCorsConfiguration.setAllowedMethods(Arrays.asList("GET"));
                    defaultCorsConfiguration.setAllowedHeaders(Arrays.asList());
                    defaultCorsConfiguration.setAllowCredentials(false);
                    defaultCorsConfiguration.setMaxAge(300L);
                    return defaultCorsConfiguration;
                };

                cors.configurationSource(openApiCorsConfigurationSource);
            });

            http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            http.anonymous().disable();
            http.csrf().disable();
            http.exceptionHandling().disable();
            http.formLogin().disable();
            http.httpBasic().disable();
            http.logout().disable();
            http.rememberMe().disable();
            http.requestCache().disable();
        }
    }

    @Configuration
    public static class DefaultSecurityConfiguration extends WebSecurityConfigurerAdapter {

        @Autowired
        private AuthenticationService authenticationService;

        @Autowired
        private ObjectMapper objectMapper;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.headers(headers -> {
                headers.cacheControl();
                headers.frameOptions().deny();
                headers.httpStrictTransportSecurity()
                    .maxAgeInSeconds(63072000)
                    .includeSubDomains(true)
                    .preload(true);
                headers.xssProtection().block(true);
                headers.contentSecurityPolicy(csp ->
                    csp.policyDirectives(
                        "default-src 'none'; " +
                            "base-uri 'self'; " +
                            "form-action 'none'; " +
                            "frame-ancestors 'none'; " +
                            "img-src 'self'; " +
                            "script-src 'self'; " +
                            "style-src 'self' 'unsafe-inline'; " +
                            "font-src 'self';"
                    )
                );
                headers.referrerPolicy().policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER);
                headers.featurePolicy(
                    "geolocation 'none'; " +
                        "midi 'none'; " +
                        "notifications 'none'; " +
                        "push 'none'; " +
                        "sync-xhr 'none'; " +
                        "microphone 'none'; " +
                        "camera 'none'; " +
                        "magnetometer 'none'; " +
                        "gyroscope 'none'; " +
                        "speaker 'none'; " +
                        "vibrate 'none'; " +
                        "fullscreen 'none'; " +
                        "payment 'none';"
                );
            });

            http.cors(cors -> {
                CorsConfigurationSource defaultCorsConfigurationSource = httpServletRequest -> {
                    CorsConfiguration defaultCorsConfiguration = new CorsConfiguration();
                    defaultCorsConfiguration.setAllowedOrigins(Arrays.asList("https://app.diplomatiq.org"));
                    defaultCorsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT"));
                    defaultCorsConfiguration.setAllowedHeaders(Arrays.asList(
                        "Authorization",
                        "ClientId",
                        "Content-Type",
                        "DeviceId",
                        "EncryptedSessionId",
                        "SignedHeaders",
                        "Timestamp"
                    ));
                    defaultCorsConfiguration.setAllowCredentials(true);
                    defaultCorsConfiguration.setMaxAge(300L);
                    return defaultCorsConfiguration;
                };

                cors.configurationSource(defaultCorsConfigurationSource);
            });

            http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            RequestMatcher authFiltersRequestMatcher =
                httpServletRequest ->
                    !ControllerPathLister.getPaths(UnauthenticatedMethods.class)
                        .contains(httpServletRequest.getServletPath());
            http.addFilterAfter(new RequestSignatureVerificationFilter(authFiltersRequestMatcher, authenticationService, objectMapper), LogoutFilter.class);
            http.addFilterAfter(new SessionAuthenticationFilter(authFiltersRequestMatcher, authenticationService,
                    objectMapper),
                RequestSignatureVerificationFilter.class);

            http.anonymous().disable();
            http.csrf().disable();
            http.exceptionHandling().disable();
            http.formLogin().disable();
            http.httpBasic().disable();
            http.logout().disable();
            http.rememberMe().disable();
            http.requestCache().disable();
        }

    }

}
