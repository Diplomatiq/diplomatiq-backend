package org.diplomatiq.diplomatiqbackend.methods.utils;

import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqAuthenticationScheme;
import org.springframework.http.HttpHeaders;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

public class HeadersProvider {
    private static final String DIPLOMATIQ_TEST_CLIENT_ID = "DiplomatiqTestClient/1.0.0";

    public static void unauthenticated(HttpHeaders httpHeaders) {
        httpHeaders.set("ClientId", DIPLOMATIQ_TEST_CLIENT_ID);
        httpHeaders.set("Instant", Instant.now().toString());
    }

    public static void authenticationSessionSignatureV1(HttpHeaders httpHeaders,
                                                        String httpRequestMethod,
                                                        String uri,
                                                        String queryString,
                                                        String payloadString,
                                                        String authenticationSessionId,
                                                        byte[] requestSigningKey)
        throws NoSuchAlgorithmException, InvalidKeyException {
        DiplomatiqAuthenticationScheme authenticationScheme =
            DiplomatiqAuthenticationScheme.AuthenticationSessionSignatureV1;

        Map<String, String> signedHeaders = Map.ofEntries(
            Map.entry("AuthenticationSessionId", authenticationSessionId),
            Map.entry("ClientId", DIPLOMATIQ_TEST_CLIENT_ID),
            Map.entry("Instant", Instant.now().toString()),
            Map.entry("SignedHeaders", "authenticationsessionid;clientid;instant;signedheaders")
        );

        signedHeaders.forEach(httpHeaders::set);

        String canonicalHeaders = signedHeaders.entrySet().stream()
            .map(e -> String.format("%s:%s", e.getKey().toLowerCase(), e.getValue()))
            .collect(Collectors.joining("\n"));

        byte[] payloadBytes = payloadString.getBytes(StandardCharsets.UTF_8);
        byte[] payloadHash = MessageDigest.getInstance("SHA-256").digest(payloadBytes);
        String payloadHashBase64 = Base64.getEncoder().encodeToString(payloadHash);

        String canonicalRequest = String.format("%s\n%s\n%s\n%s\n%s", httpRequestMethod, uri, queryString,
            canonicalHeaders, payloadHashBase64);

        byte[] canonicalRequestHash =
            MessageDigest.getInstance("SHA-256").digest(canonicalRequest.getBytes(StandardCharsets.UTF_8));
        String canonicalRequestHashBase64 = Base64.getEncoder().encodeToString(canonicalRequestHash);
        String stringToSign = String.format("%s %s",
            authenticationScheme.name(), canonicalRequestHashBase64);

        SecretKeySpec requestSigningKeySpec = new SecretKeySpec(requestSigningKey, "HmacSHA256");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(requestSigningKeySpec);
        byte[] signatureBytes = mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8));
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

        String authorizationHeaderValue = String.format("%s %s", authenticationScheme.name(), signatureBase64);

        httpHeaders.set("Authorization", authorizationHeaderValue);
    }
}
