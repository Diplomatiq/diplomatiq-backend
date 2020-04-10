package org.diplomatiq.diplomatiqbackend.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.filters.authentication.SessionAuthenticationFilter;
import org.diplomatiq.diplomatiqbackend.filters.signature.RequestSignatureVerificationFilter;
import org.diplomatiq.diplomatiqbackend.methods.controllers.UnauthenticatedMethods;
import org.diplomatiq.diplomatiqbackend.methods.utils.ControllerPathLister;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        configureSecurityHeaders(http);
        configureCors(http);
        configureSessionManagement(http);
        configureAuthFilters(http);
        disableUnusedAutoConfiguredFeatures(http);
    }

    private void configureSecurityHeaders(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.headers(headers -> {
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
                        "font-src 'self'" +
                        ";"
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
    }

    private void configureCors(HttpSecurity http) throws Exception {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(Arrays.asList("https://app.diplomatiq.org"));
        corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT"));
        corsConfiguration.setAllowedHeaders(Arrays.asList(
            "Authorization",
            "ClientId",
            "Content-Type",
            "DeviceId",
            "EncryptedSessionId",
            "SignedHeaders",
            "Timestamp"
        ));
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setMaxAge(300L);

        UrlBasedCorsConfigurationSource corsConfigurationSource = new UrlBasedCorsConfigurationSource();
        corsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);

        http.cors().configurationSource(corsConfigurationSource);
    }

    private void configureAuthFilters(HttpSecurity http) throws Exception {
        RequestMatcher filterRequestMatcher =
            httpServletRequest -> !ControllerPathLister.getPaths(UnauthenticatedMethods.class)
                .contains(httpServletRequest.getRequestURI());
        http.addFilterAfter(new RequestSignatureVerificationFilter(filterRequestMatcher), LogoutFilter.class);
        http.addFilterAfter(new SessionAuthenticationFilter(filterRequestMatcher, authenticationService, objectMapper),
            RequestSignatureVerificationFilter.class);
    }

    private void configureSessionManagement(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    private void disableUnusedAutoConfiguredFeatures(HttpSecurity http) throws Exception {
        http.anonymous().disable();
        http.exceptionHandling().disable();
        http.formLogin().disable();
        http.httpBasic().disable();
        http.logout().disable();
        http.csrf().disable();
    }

}
