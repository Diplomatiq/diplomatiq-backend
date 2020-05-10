package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.Committee;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface CommitteeRepository extends Neo4jRepository<Committee, String> {
}
