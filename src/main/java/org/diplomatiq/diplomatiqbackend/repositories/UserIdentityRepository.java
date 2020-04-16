package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserIdentityRepository extends Neo4jRepository<UserIdentity, String> {
    Optional<UserIdentity> findByEmailAddress(String emailAddress);
    Optional<UserIdentity> findByEmailAddressDigestBase64(String emailAddressDigestBase64);
}
