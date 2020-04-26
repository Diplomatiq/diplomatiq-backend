package org.diplomatiq.diplomatiqbackend.methods;

import org.junit.jupiter.api.Test;
import org.neo4j.ogm.config.Configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.neo4j.DataNeo4jTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DataNeo4jTest
class UnauthenticatedMethodsTests {
    @TestConfiguration
    static class Config {
        @Bean
        public org.neo4j.ogm.config.Configuration configuration() {
            return new Configuration.Builder().build();
        }
    }

    @Autowired
    WebTestClient webTestClient;

    @Test
    public void rootRedirect() {
        webTestClient.get().uri("/").exchange()
            .expectStatus().isTemporaryRedirect()
            .expectHeader().valueEquals("Location", "https://www.diplomatiq.org");
    }

    public void throwIfHeadersMissing() {
//        webTestClient.

    }

    public void registerUserV1Test() {
//        HttpHeaders headers = new HttpHeaders();
//        headers.add("Instant");
//
//        webTestClient.post()
//            .uri("/register-user-v1")
//            .contentType(MediaType.APPLICATION_JSON)
//            .headers()
    }
}
