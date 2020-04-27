package org.diplomatiq.diplomatiqbackend.methods.utils;

import org.springframework.http.HttpHeaders;

import java.time.Instant;

public class HeadersProvider {
    private static final String DIPLOMATIQ_TEST_CLIENT_ID = "DiplomatiqTestClient/1.0.0";

    public static void unauthenticated(HttpHeaders httpHeaders) {
        httpHeaders.set("ClientId", DIPLOMATIQ_TEST_CLIENT_ID);
        httpHeaders.set("Instant", Instant.now().toString());
    }
}
