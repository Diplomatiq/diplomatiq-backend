package org.diplomatiq.diplomatiqbackend;

import org.neo4j.ogm.config.Configuration;
import org.springframework.boot.test.autoconfigure.data.neo4j.DataNeo4jTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@DataNeo4jTest
public class Neo4jExampleTest {
    @TestConfiguration
    static class Config {
        @Bean
        public org.neo4j.ogm.config.Configuration configuration() {
            return new Configuration.Builder().build();
        }
    }
}
