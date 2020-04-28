package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserTemporarySRPData;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserTemporarySRPDataRepository extends Neo4jRepository<UserTemporarySRPData, String> {
}
