package org.diplomatiq.diplomatiqbackend.methods.controllers.unauthenticated;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthentication;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.UserIdentityHelper;
import org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.PasswordStretchingAlgorithm;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.RegisterUserV1Request;
import org.diplomatiq.diplomatiqbackend.methods.utils.HeadersProvider;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.RandomUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class RegisterUserV1Tests {
    private final String uri = "/register-user-v1";

    @Autowired
    WebTestClient webTestClient;

    @Autowired
    UserIdentityRepository userIdentityRepository;

    @Autowired
    UserIdentityHelper userIdentityHelper;

    @Test
    public void throwIfHeadersMissing() {
        webTestClient.post().uri(uri).exchange()
            .expectStatus().isBadRequest()
            .expectHeader().contentType(MediaType.APPLICATION_JSON_UTF8)
            .expectBody().jsonPath("$.errorCode", "BadRequest");
    }

    @Test
    public void throwIfClockDiscrepancy() {
        webTestClient.post().uri(uri)
            .accept(MediaType.APPLICATION_JSON)
            .headers(httpHeaders -> {
                httpHeaders.set("ClientId", "test");
                httpHeaders.set("Instant", Instant.now().plus(Duration.ofMinutes(2)).toString());
            })
            .exchange()
            .expectStatus().isBadRequest()
            .expectHeader().contentType(MediaType.APPLICATION_JSON_UTF8)
            .expectBody().jsonPath("$.errorCode", "BadRequest");
    }

    @Test
    public void throwIfEmptyBody() {
        webTestClient.post().uri(uri)
            .headers(HeadersProvider::unauthenticated)
            .contentType(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectHeader().contentType(MediaType.APPLICATION_JSON_UTF8)
            .expectBody().jsonPath("$.errorCode", "BadRequest");
    }

    @Test
    public void shouldRegisterUser() {
        String emailAddress = "samspi0l@diplomatiq.org";
        String firstName = "Sam";
        String lastName = "Sepiol";
        byte[] srpSaltBytes = RandomUtils.bytes(32);
        String srpSaltBase64 = Base64.getEncoder().encodeToString(srpSaltBytes);
        String srpVerifierBase64 = Base64.getEncoder().encodeToString(RandomUtils.bytes(8192));
        PasswordStretchingAlgorithm passwordStretchingAlgorithm = PasswordStretchingAlgorithm.Argon2_v1;

        RegisterUserV1Request request = new RegisterUserV1Request();
        request.setEmailAddress(emailAddress);
        request.setFirstName(firstName);
        request.setLastName(lastName);
        request.setSrpSaltBase64(srpSaltBase64);
        request.setSrpVerifierBase64(srpVerifierBase64);
        request.setPasswordStretchingAlgorithm(passwordStretchingAlgorithm);

        webTestClient.post().uri(uri)
            .headers(HeadersProvider::unauthenticated)
            .body(Mono.just(request), RegisterUserV1Request.class)
            .exchange()
            .expectStatus().isOk()
            .expectBody().isEmpty();

        UserIdentity userIdentity = userIdentityRepository.findByEmailAddress(emailAddress).orElseThrow();
        Assertions.assertEquals(emailAddress, userIdentity.getEmailAddress());
        Assertions.assertEquals(firstName, userIdentity.getFirstName());
        Assertions.assertEquals(lastName, userIdentity.getLastName());

        Set<UserAuthentication> userAuthentications = userIdentity.getAuthentications();
        Assertions.assertEquals(1, userAuthentications.size());

        UserAuthentication userAuthentication = userIdentityHelper.getCurrentAuthentication(userIdentity);
        Assertions.assertArrayEquals(srpSaltBytes, userAuthentication.getSrpSalt());
        Assertions.assertArrayEquals(srpSaltBytes, userAuthentication.getSrpSalt());
        Assertions.assertEquals(PasswordStretchingAlgorithm.Argon2_v1,
            userAuthentication.getPasswordStretchingAlgorithm());
    }
}
