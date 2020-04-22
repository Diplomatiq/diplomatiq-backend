package org.diplomatiq.diplomatiqbackend.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.exceptions.GlobalExceptionHandler;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqHeaders;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqMethods;
import org.diplomatiq.diplomatiqbackend.filters.authentication.AuthenticationFilter;
import org.diplomatiq.diplomatiqbackend.filters.signature.RequestSignatureVerificationFilter;
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;

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
                    defaultCorsConfiguration.setAllowedOrigins(Collections.singletonList("*"));
                    defaultCorsConfiguration.setAllowedMethods(Collections.singletonList("GET"));
                    defaultCorsConfiguration.setAllowedHeaders(Collections.emptyList());
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
        private final Set<String> UNAUTHENTICATED_PATHS = Collections.unmodifiableSet(
            Set.of(
                "/",
                "/get-device-container-key-v1",
                "/password-authentication-complete-v1",
                "/password-authentication-init-v1",
                "/register-user-v1"
            )
        );

        @Autowired
        private AuthenticationService authenticationService;

        @Autowired
        private ObjectMapper objectMapper;

        @Autowired
        private GlobalExceptionHandler globalExceptionHandler;

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
                    defaultCorsConfiguration.setAllowedOrigins(Collections.singletonList("https://app.diplomatiq.org"));
                    defaultCorsConfiguration.setAllowedMethods(new ArrayList<>(DiplomatiqMethods.AllowedMethods));
                    defaultCorsConfiguration.setAllowedHeaders(new ArrayList<>(DiplomatiqHeaders.AllKnownHeaders));
                    defaultCorsConfiguration.setAllowCredentials(true);
                    defaultCorsConfiguration.setMaxAge(300L);
                    return defaultCorsConfiguration;
                };

                cors.configurationSource(defaultCorsConfigurationSource);
            });

            http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            RequestMatcher authFiltersRequestMatcher =
                httpServletRequest -> !UNAUTHENTICATED_PATHS.contains(httpServletRequest.getServletPath());
            http.addFilterAfter(new RequestSignatureVerificationFilter(authFiltersRequestMatcher, objectMapper,
                authenticationService, globalExceptionHandler), LogoutFilter.class);
            http.addFilterAfter(new AuthenticationFilter(authFiltersRequestMatcher, objectMapper,
                    authenticationService, globalExceptionHandler),
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
