//package org.diplomatiq.diplomatiqbackend.configuration;
//
//import org.neo4j.ogm.session.SessionFactory;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Profile;
//import org.springframework.data.neo4j.repository.config.EnableNeo4jRepositories;
//import org.springframework.data.neo4j.transaction.Neo4jTransactionManager;
//import org.springframework.transaction.annotation.EnableTransactionManagement;
//
//@Configuration
//@EnableNeo4jRepositories("org.diplomatiq.diplomatiqbackend.repositories")
//@EnableTransactionManagement
//@Profile("testing")
//public class Neo4jTestConfiguration {
//    @Bean
//    public SessionFactory sessionFactory() {
//        return new SessionFactory(configuration(), "org.diplomatiq.diplomatiqbackend.domain.entities.concretes");
//    }
//
//    @Bean
//    public org.neo4j.ogm.config.Configuration configuration() {
//        return new org.neo4j.ogm.config.Configuration.Builder().build();
//    }
//
//    @Bean
//    public Neo4jTransactionManager transactionManager() {
//        return new Neo4jTransactionManager(sessionFactory());
//    }
//}
