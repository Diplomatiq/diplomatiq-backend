package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.SessionMultiFactorElevationRequest;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface SessionMultiFactorElevationRequestRepository extends Neo4jRepository<SessionMultiFactorElevationRequest, String> {
}
