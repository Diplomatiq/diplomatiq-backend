package org.diplomatiq.diplomatiqbackend.methods;

import org.springframework.test.web.reactive.server.WebTestClient;

public abstract class AbstractIntegrationTest {
    protected abstract WebTestClient getWebTestClient();
}
