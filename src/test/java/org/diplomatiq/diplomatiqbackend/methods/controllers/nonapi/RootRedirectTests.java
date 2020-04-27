package org.diplomatiq.diplomatiqbackend.methods.controllers.nonapi;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("testing")
public class RootRedirectTests {
    @Autowired
    WebTestClient webTestClient;

    @Test
    public void rootRedirect() {
        webTestClient.get().uri("/").exchange()
            .expectStatus().isTemporaryRedirect()
            .expectHeader().valueEquals("Location", "https://www.diplomatiq.org")
            .expectBody().isEmpty();
    }
}
