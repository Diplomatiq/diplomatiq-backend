package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.Conference;

import java.time.LocalDate;
import java.util.Locale;

public class ConferenceHelper {
    public static Conference create(String name, String codeName, LocalDate from, LocalDate to,
                                    String country, String city, String address, String postalCode) {
        Conference conference = new Conference();

        conference.setName(name);
        conference.setCodeName(codeName);
        conference.setFrom(from);
        conference.setTo(to);
        conference.setCountry(country);
        conference.setCity(city);
        conference.setAddress(address);
        conference.setPostalCode(postalCode);

        return conference;
    }
}
