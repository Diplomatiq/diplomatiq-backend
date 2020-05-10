package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.CommitteeSeat;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface CommitteeSeatRepository extends Neo4jRepository<CommitteeSeat, String> {
}
