package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.Committee;

public class CommitteeHelper {
    public static Committee create(String name, String code) {
        Committee conference = new Committee();

        conference.setName(name);
        conference.setCodeName(code);

        return conference;
    }
}
