package org.diplomatiq.diplomatiqbackend.configuration;

import org.neo4j.ogm.session.SessionFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.neo4j.repository.config.EnableNeo4jRepositories;
import org.springframework.data.neo4j.transaction.Neo4jTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration
@EnableNeo4jRepositories("org.diplomatiq.diplomatiqbackend.repositories")
@EnableTransactionManagement
public class Neo4jConfiguration {

    @Value("${NEO4J_URI:bolt://localhost:7687}")
    private String uri;

    @Value("${NEO4J_DATABASE:neo4j}")
    private String database;

    @Value("${NEO4J_USERNAME:neo4j}")
    private String username;

    @Value("${NEO4J_PASSWORD:secret}")
    private String password;

    @Bean
    public SessionFactory sessionFactory() {
        return new SessionFactory(configuration(), "org.diplomatiq.diplomatiqbackend.entities");
    }

    @Bean
    public org.neo4j.ogm.config.Configuration configuration() {
        return new org.neo4j.ogm.config.Configuration.Builder()
            .uri(uri)
            .database(database)
            .credentials(username, password)
            .build();
    }

    @Bean
    public Neo4jTransactionManager transactionManager() {
        return new Neo4jTransactionManager(sessionFactory());
    }

}
