package org.diplomatiq.diplomatiqbackend.filters.signature;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.exceptions.api.UnauthorizedException;
import org.diplomatiq.diplomatiqbackend.filters.RequestMatchingGenericFilterBean;
import org.diplomatiq.diplomatiqbackend.filters.signature.AuthenticationScheme.DiplomatiqAuthenticationScheme;
import org.diplomatiq.diplomatiqbackend.filters.signature.RequestSigningAlgorithm.DiplomatiqRequestSigningAlgorithm;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.ContentCachingRequestWrapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
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

public class RequestSignatureVerificationFilter extends RequestMatchingGenericFilterBean {

    private AuthenticationService authenticationService;
    private ObjectMapper objectMapper;

    public RequestSignatureVerificationFilter(RequestMatcher requestMatcher,
                                              AuthenticationService authenticationService, ObjectMapper objectMapper) {
        super(requestMatcher);
        this.authenticationService = authenticationService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void doFilterIfRequestMatches(ServletRequest servletRequest, ServletResponse servletResponse,
                                         FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request);
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        try {
            verifySignature(wrappedRequest);
            filterChain.doFilter(wrappedRequest, servletResponse);
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            objectMapper.writeValue(response.getWriter(), new UnauthorizedException());
        }

    }

    private void verifySignature(ContentCachingRequestWrapper request) throws NoSuchAlgorithmException,
        InvalidKeyException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || authorizationHeader.equals("")) {
            throw new RuntimeException("Authorization header must not be null or empty");
        }

        String[] authorizationHeaderSplit = authorizationHeader.split(" ");
        DiplomatiqAuthenticationScheme authenticationScheme =
            AuthenticationScheme.fromString(authorizationHeaderSplit[0]);

        switch (authenticationScheme) {
            case SignedSession:
                verifySignedSessionSignature(request, authorizationHeaderSplit);
                break;

            default:
                throw new RuntimeException("unknown authentication scheme");
        }
    }

    private void verifySignedSessionSignature(ContentCachingRequestWrapper request,
                                              String[] authorizationHeaderSplit) throws NoSuchAlgorithmException,
        InvalidKeyException {
        DiplomatiqRequestSigningAlgorithm requestSigningAlgorithm =
            RequestSigningAlgorithm.fromString(authorizationHeaderSplit[1]);

        Base64.Decoder base64Decoder = Base64.getDecoder();
        byte[] providedSignature = base64Decoder.decode(authorizationHeaderSplit[3].getBytes(StandardCharsets.UTF_8));

        String httpRequestMethod = request.getMethod();
        String uri = request.getRequestURI();
        String queryString = request.getQueryString();

        String signedHeaderNamesString = request.getHeader("SignedHeaders");
        if (signedHeaderNamesString == null || signedHeaderNamesString.equals("")) {
            throw new RuntimeException("SignedHeaders must not be null or empty");
        }

        Set<String> signedHeaderNames = Set.of(signedHeaderNamesString.split(";"));
        for (String mandatoryHeaderName : DiplomatiqHeaders.RequiredSignedHeaders) {
            if (!signedHeaderNames.contains(mandatoryHeaderName.toLowerCase())) {
                throw new RuntimeException(mandatoryHeaderName + " is missing from SignedHeaders");
            }
        }

        SortedMap<String, String> signedHeaders = new TreeMap<>();
        for (String signedHeaderName : signedHeaderNames) {
            String signedHeaderValue = request.getHeader(signedHeaderName);
            if (signedHeaderValue == null || signedHeaderValue.equals("")) {
                throw new RuntimeException("signed header not found among headers");
            }
            signedHeaders.put(signedHeaderName.toLowerCase(), signedHeaderValue);
        }

        Base64.Encoder base64Encoder = Base64.getEncoder();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        byte[] payload = request.getContentAsByteArray();
        byte[] payloadHash = sha256.digest(payload);
        String payloadHashBase64 = base64Encoder.encodeToString(payloadHash);

        String canonicalHeaders = signedHeaders.entrySet().stream()
            .map(e -> e.getKey() + ":" + e.getValue())
            .collect(Collectors.joining("\n"));

        String canonicalRequest = httpRequestMethod + "\n" +
            uri + "\n" +
            queryString + "\n" +
            canonicalHeaders + "\n" +
            payloadHashBase64;

        byte[] canonicalRequestHash = sha256.digest(canonicalRequest.getBytes(StandardCharsets.UTF_8));
        String canonicalRequestHashBase64 = base64Encoder.encodeToString(canonicalRequestHash);
        String stringToSign = requestSigningAlgorithm.string + " " + canonicalRequestHashBase64;

        String deviceId = signedHeaders.get("DeviceId".toLowerCase());
        byte[] deviceKeyRaw = authenticationService.getDeviceKeyByDeviceId(deviceId);
        SecretKeySpec deviceKey = new SecretKeySpec(deviceKeyRaw, "HmacSHA256");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(deviceKey);
        byte[] expectedSignature = mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8));

        if (!MessageDigest.isEqual(expectedSignature, providedSignature)) {
            throw new RuntimeException("request signature mismatch");
        }
    }

}
