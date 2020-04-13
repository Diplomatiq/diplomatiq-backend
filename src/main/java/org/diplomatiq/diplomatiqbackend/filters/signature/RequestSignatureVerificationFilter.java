package org.diplomatiq.diplomatiqbackend.filters.signature;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiException;
import org.diplomatiq.diplomatiqbackend.exceptions.api.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.exceptions.http.MethodNotAllowedException;
import org.diplomatiq.diplomatiqbackend.filters.RequestMatchingFilter;
import org.diplomatiq.diplomatiqbackend.filters.signature.AuthenticationScheme.DiplomatiqAuthenticationScheme;
import org.diplomatiq.diplomatiqbackend.filters.signature.RequestSigningAlgorithm.DiplomatiqRequestSigningAlgorithm;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.ContentCachingRequestWrapper;

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
import java.util.Base64;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class RequestSignatureVerificationFilter extends RequestMatchingFilter {

    private AuthenticationService authenticationService;

    public RequestSignatureVerificationFilter(RequestMatcher requestMatcher, ObjectMapper objectMapper,
                                              AuthenticationService authenticationService) {
        super(requestMatcher, objectMapper);
        this.authenticationService = authenticationService;
    }

    @Override
    public void doFilterIfRequestMatches(ServletRequest servletRequest, ServletResponse servletResponse,
                                         FilterChain filterChain) throws IOException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request);
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        try {
            verifySignature(wrappedRequest);
            filterChain.doFilter(wrappedRequest, servletResponse);
        } catch (DiplomatiqApiException ex) {
            writeJsonErrorResponse(response, ex);
        } catch (Exception ex) {
            writeJsonErrorResponse(response, new UnauthorizedException("Signature verification failed because of an " +
                "unknown error.", ex));
        }

    }

    private void verifySignature(ContentCachingRequestWrapper request) throws NoSuchAlgorithmException,
        InvalidKeyException, UnauthorizedException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || authorizationHeader.equals("")) {
            throw new UnauthorizedException("Authorization header must not be null or empty.", null);
        }

        String[] authorizationHeaderSplit = authorizationHeader.split(" ");

        DiplomatiqAuthenticationScheme authenticationScheme;
        try {
            authenticationScheme = AuthenticationScheme.fromString(authorizationHeaderSplit[0]);
        } catch (IllegalArgumentException ex) {
            throw new UnauthorizedException("Unknown authentication scheme.", ex);
        }

        switch (authenticationScheme) {
            case SignedSession:
                verifySignedSessionSignature(request, authorizationHeaderSplit);
                break;

            default:
                throw new UnauthorizedException("Unknown authentication scheme.", null);
        }
    }

    private void verifySignedSessionSignature(ContentCachingRequestWrapper request,
                                              String[] authorizationHeaderSplit) throws NoSuchAlgorithmException,
        InvalidKeyException {
        DiplomatiqRequestSigningAlgorithm requestSigningAlgorithm;

        try {
            requestSigningAlgorithm = RequestSigningAlgorithm.fromString(authorizationHeaderSplit[1]);
        } catch (IllegalArgumentException ex) {
            throw new UnauthorizedException("Unknown signature algorithm.", ex);
        }

        Base64.Decoder base64Decoder = Base64.getDecoder();
        byte[] providedSignature;

        try {
            providedSignature = base64Decoder.decode(authorizationHeaderSplit[2].getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new UnauthorizedException("Could not decode base64 signature.", ex);
        }

        String httpRequestMethod = request.getMethod().toUpperCase();
        if (!DiplomatiqMethods.AllowedRequestMethods.contains(httpRequestMethod)) {
            throw new MethodNotAllowedException(String.format("Method %s is not allowed.", httpRequestMethod), null);
        }

        String uri = request.getRequestURI();
        String queryString = request.getQueryString();

        String signedHeaderNamesString = request.getHeader("SignedHeaders");
        if (signedHeaderNamesString == null || signedHeaderNamesString.equals("")) {
            throw new UnauthorizedException("SignedHeaders header must not be null or empty.", null);
        }

        Set<String> signedHeaderNames = Set.of(signedHeaderNamesString.split(";"));
        for (String mandatoryHeaderName : DiplomatiqHeaders.RequiredSignedHeaders.get(httpRequestMethod)) {
            if (!signedHeaderNames.contains(mandatoryHeaderName.toLowerCase())) {
                throw new UnauthorizedException(String.format("Mandatory header %s is missing from SignedHeaders.",
                    mandatoryHeaderName), null);
            }
        }

        SortedMap<String, String> signedHeaders = new TreeMap<>();
        for (String signedHeaderName : signedHeaderNames) {
            String signedHeaderValue = request.getHeader(signedHeaderName);
            if (signedHeaderValue == null || signedHeaderValue.equals("")) {
                throw new UnauthorizedException(String.format("Signed header %s not found among headers.",
                    signedHeaderName), null);
            }
            signedHeaders.put(signedHeaderName.toLowerCase(), signedHeaderValue);
        }

        Base64.Encoder base64Encoder = Base64.getEncoder();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        byte[] payload = request.getContentAsByteArray();
        byte[] payloadHash = sha256.digest(payload);
        String payloadHashBase64 = base64Encoder.encodeToString(payloadHash);

        String canonicalHeaders = signedHeaders.entrySet().stream()
            .map(e -> String.format("%s:%s", e.getKey(), e.getValue()))
            .collect(Collectors.joining("\n"));

        String canonicalRequest = String.format("%s\n%s\n%s\n%s\n%s", httpRequestMethod, uri, queryString,
            canonicalHeaders, payloadHashBase64);

        byte[] canonicalRequestHash = sha256.digest(canonicalRequest.getBytes(StandardCharsets.UTF_8));
        String canonicalRequestHashBase64 = base64Encoder.encodeToString(canonicalRequestHash);
        String stringToSign = String.format("%s %s", requestSigningAlgorithm.string, canonicalRequestHashBase64);

        String deviceId = signedHeaders.get("DeviceId".toLowerCase());
        byte[] deviceKeyRaw = authenticationService.getDeviceKeyByDeviceId(deviceId);
        SecretKeySpec deviceKey = new SecretKeySpec(deviceKeyRaw, "HmacSHA256");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(deviceKey);
        byte[] expectedSignature = mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8));

        if (!MessageDigest.isEqual(expectedSignature, providedSignature)) {
            throw new UnauthorizedException("Request signature mismatch.", null);
        }
    }

}
