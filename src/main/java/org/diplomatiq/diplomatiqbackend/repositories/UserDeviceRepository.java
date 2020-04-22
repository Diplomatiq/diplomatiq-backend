package org.diplomatiq.diplomatiqbackend.repositories;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserDevice;
import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface UserDeviceRepository extends Neo4jRepository<UserDevice, String> {
}
