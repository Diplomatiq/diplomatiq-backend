package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.Session;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionRepository extends Neo4jRepository<Session, String> {
}
