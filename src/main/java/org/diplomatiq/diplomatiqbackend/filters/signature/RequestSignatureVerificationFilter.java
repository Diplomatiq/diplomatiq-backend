package org.diplomatiq.diplomatiqbackend.filters.signature;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.exceptions.GlobalExceptionHandler;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.BadRequestException;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqAuthenticationScheme;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqHeaders;
import org.diplomatiq.diplomatiqbackend.filters.RequestMatchingFilter;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StreamUtils;
import org.springframework.web.context.request.ServletWebRequest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

public class RequestSignatureVerificationFilter extends RequestMatchingFilter {
    private AuthenticationService authenticationService;
    private GlobalExceptionHandler globalExceptionHandler;

    public RequestSignatureVerificationFilter(ObjectMapper objectMapper, RequestMatcher requestMatcher,
                                              AuthenticationService authenticationService,
                                              GlobalExceptionHandler globalExceptionHandler) {
        super(objectMapper, requestMatcher);
        this.authenticationService = authenticationService;
        this.globalExceptionHandler = globalExceptionHandler;
    }

    @Override
    public void doFilterIfRequestMatches(ServletRequest servletRequest, ServletResponse servletResponse,
                                         FilterChain filterChain) throws IOException {
        BodyCachingHttpServletRequest request = new BodyCachingHttpServletRequest((HttpServletRequest)servletRequest);
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        try {
            verifyRequestSignature(request);
            filterChain.doFilter(request, servletResponse);
        } catch (BadRequestException ex) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleBadRequestException(ex,
                new ServletWebRequest(request));
            writeJsonResponse(response, responseEntity);
        } catch (UnauthorizedException ex) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleUnauthorizedException(ex,
                new ServletWebRequest(request));
            writeJsonResponse(response, responseEntity);
        } catch (Exception ex) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleUnknownException(ex,
                new ServletWebRequest(request));
            writeJsonResponse(response, responseEntity);
        }
    }

    private void verifyRequestSignature(HttpServletRequest request) throws InvalidKeyException,
        UnauthorizedException, NoSuchAlgorithmException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || authorizationHeader.equals("")) {
            throw new BadRequestException("Authorization header must not be null or empty.");
        }

        String[] authorizationHeaderSplit = authorizationHeader.split(" ");

        String authenticationSchemeString = authorizationHeaderSplit[0];
        String signatureBase64 = authorizationHeaderSplit[1];

        DiplomatiqAuthenticationScheme authenticationScheme;
        try {
            authenticationScheme = DiplomatiqAuthenticationScheme.valueOf(authenticationSchemeString);
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Unknown authentication scheme.", ex);
        }

        byte[] providedSignature;
        try {
            providedSignature = Base64.getDecoder().decode(signatureBase64);
        } catch (Exception ex) {
            throw new BadRequestException("Could not decode the signature.", ex);
        }

        String httpRequestMethod = request.getMethod().toUpperCase();
        String uri = request.getRequestURI();
        String queryString = Optional.ofNullable(request.getQueryString()).orElse("");

        String signedHeaderNamesString = request.getHeader(DiplomatiqHeaders.KnownHeader.SignedHeaders.name());
        if (signedHeaderNamesString == null || signedHeaderNamesString.equals("")) {
            throw new BadRequestException("SignedHeaders header must not be null or empty.");
        }

        Set<String> mandatoryHeaderNames;
        switch (authenticationScheme) {
            case AuthenticationSessionSignatureV1:
                mandatoryHeaderNames = DiplomatiqHeaders.AuthenticationSessionSignatureV1SignedHeaders;
                break;

            case DeviceSignatureV1:
                mandatoryHeaderNames = DiplomatiqHeaders.DeviceSignatureV1SignedHeaders;
                break;

            case SessionSignatureV1:
                mandatoryHeaderNames = DiplomatiqHeaders.SessionSignatureV1SignedHeaders;
                break;

            default:
                throw new BadRequestException("Unknown authentication scheme.", null);
        }

        Set<String> signedHeaderNames = new LinkedHashSet<>(Arrays.asList(signedHeaderNamesString.split(";")));
        for (String mandatoryHeaderName : mandatoryHeaderNames) {
            if (!signedHeaderNames.contains(mandatoryHeaderName.toLowerCase())) {
                throw new BadRequestException(String.format("Mandatory header %s is missing from SignedHeaders.",
                    mandatoryHeaderName));
            }
        }

        Map<String, String> signedHeaders = new LinkedHashMap<>();
        for (String signedHeaderName : signedHeaderNames) {
            String signedHeaderValue = request.getHeader(signedHeaderName);
            if (signedHeaderValue == null || signedHeaderValue.equals("")) {
                throw new BadRequestException(String.format("Signed header %s not found among headers.",
                    signedHeaderName));
            }
            signedHeaders.put(signedHeaderName.toLowerCase(), signedHeaderValue);
        }

        byte[] payload = StreamUtils.copyToByteArray(request.getInputStream());
        byte[] payloadHash = MessageDigest.getInstance("SHA-256").digest(payload);
        String payloadHashBase64 = Base64.getEncoder().encodeToString(payloadHash);

        String canonicalHeaders = signedHeaders.entrySet().stream()
            .map(e -> String.format("%s:%s", e.getKey(), e.getValue()))
            .collect(Collectors.joining("\n"));

        String canonicalRequest = String.format("%s\n%s\n%s\n%s\n%s", httpRequestMethod, uri, queryString,
            canonicalHeaders, payloadHashBase64);

        byte[] canonicalRequestHash =
            MessageDigest.getInstance("SHA-256").digest(canonicalRequest.getBytes(StandardCharsets.UTF_8));
        String canonicalRequestHashBase64 = Base64.getEncoder().encodeToString(canonicalRequestHash);
        String stringToSign = String.format("%s %s", authenticationScheme.name(), canonicalRequestHashBase64);

        byte[] requestSigningKey;
        switch (authenticationScheme) {
            case AuthenticationSessionSignatureV1:
                String authenticationSessionId =
                    signedHeaders.get(DiplomatiqHeaders.KnownHeader.AuthenticationSessionId.name().toLowerCase());
                try {
                    requestSigningKey =
                        authenticationService.getAuthenticationSessionKeyByAuthenticationSessionId(authenticationSessionId);
                } catch (Exception ex) {
                    throw new UnauthorizedException("Authentication session key could not be retrieved.");
                }
                break;

            case DeviceSignatureV1:
            case SessionSignatureV1:
                String deviceId = signedHeaders.get("DeviceId".toLowerCase());
                try {
                    requestSigningKey = authenticationService.getDeviceKeyByDeviceId(deviceId);
                } catch (Exception ex) {
                    throw new UnauthorizedException("Device key could not be retrieved.");
                }
                break;

            default:
                throw new BadRequestException("Unknown authentication scheme.", null);
        }

        SecretKeySpec requestSigningKeySpec = new SecretKeySpec(requestSigningKey, "HmacSHA256");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(requestSigningKeySpec);
        byte[] expectedSignature = mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8));

        if (!MessageDigest.isEqual(expectedSignature, providedSignature)) {
            throw new UnauthorizedException("Request signature mismatch.");
        }
    }
}
