package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.Conference;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface ConferenceRepository extends Neo4jRepository<Conference, String> {
    boolean existsByName(String name);
    boolean existsByCodeName(String codeName);
}
