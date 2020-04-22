package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.AuthenticationSession;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface AuthenticationSessionRepository extends Neo4jRepository<AuthenticationSession, String> {
}
