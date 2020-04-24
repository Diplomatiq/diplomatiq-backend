package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthenticationResetRequest;
import org.springframework.data.neo4j.repository.Neo4jRepository;

import java.util.Optional;

public interface UserAuthenticationResetRequestRepository extends Neo4jRepository<UserAuthenticationResetRequest, String> {
    Optional<UserAuthenticationResetRequest> findByRequestKey(String requestKey);
}
