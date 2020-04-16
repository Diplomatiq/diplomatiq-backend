package org.diplomatiq.diplomatiqbackend.domain.entities.abstracts;

import org.diplomatiq.diplomatiqbackend.utils.crypto.random.EntityIdGenerator;
import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;

public abstract class AbstractIdentifiableNodeEntity {
    @Id
    @GeneratedValue(strategy = EntityIdGenerator.class)
    private String id;

    public final String getId() {
        return id;
    }
}
