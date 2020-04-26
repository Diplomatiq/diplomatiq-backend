package org.diplomatiq.diplomatiqbackend;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class UnauthenticatedMethodsTests {
    @Autowired
    WebTestClient webTestClient;

    @Test
    public void rootRedirect() {
        webTestClient.get().uri("/").exchange()
            .expectStatus().isTemporaryRedirect()
            .expectHeader().valueEquals("Location", "https://www.diplomatiq.org");
    }
}
