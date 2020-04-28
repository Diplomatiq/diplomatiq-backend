package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthenticationResetRequest;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAuthenticationResetRequestRepository extends Neo4jRepository<UserAuthenticationResetRequest, String> {
    Optional<UserAuthenticationResetRequest> findByRequestKey(String requestKey);
}
