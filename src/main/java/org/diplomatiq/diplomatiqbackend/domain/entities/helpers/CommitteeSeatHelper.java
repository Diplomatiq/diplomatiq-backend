package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.CommitteeSeat;

public class CommitteeSeatHelper {
    public static CommitteeSeat create(String country) {
        CommitteeSeat conference = new CommitteeSeat();

        conference.setRepresentedCountry(country);

        return conference;
    }
}
