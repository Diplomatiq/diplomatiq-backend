package org.diplomatiq.diplomatiqbackend.services;

import org.diplomatiq.diplomatiqbackend.domain.entities.abstracts.AbstractIdentifiableNodeEntity;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.Committee;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.CommitteeSeat;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.Conference;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.CommitteeHelper;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.CommitteeSeatHelper;
import org.diplomatiq.diplomatiqbackend.domain.entities.helpers.ConferenceHelper;
import org.diplomatiq.diplomatiqbackend.engines.mail.EmailSendingEngine;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.BadRequestException;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.InternalServerError;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.ApplyConferenceV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.CancelApplicationV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.CancelConferenceV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.OrganizeConferenceV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.subentities.CommitteeWithSeats;
import org.diplomatiq.diplomatiqbackend.repositories.CommitteeRepository;
import org.diplomatiq.diplomatiqbackend.repositories.CommitteeSeatRepository;
import org.diplomatiq.diplomatiqbackend.repositories.ConferenceRepository;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.LocalDate;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

@Service
@Transactional
public class ConferenceService {
    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private EmailSendingEngine emailSendingEngine;

    @Autowired
    private ConferenceRepository conferenceRepository;

    @Autowired
    private CommitteeRepository committeeRepository;

    @Autowired
    private CommitteeSeatRepository committeeSeatRepository;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    public void organizeConferenceV1(OrganizeConferenceV1Request request) {
        String conferenceName = request.getConferenceName();
        String conferenceCodeName = request.getConferenceCodeName();
        LocalDate conferenceFrom = LocalDate.parse(request.getConferenceFrom());
        LocalDate conferenceTo = LocalDate.parse(request.getConferenceTo());

        String conferenceCountry = request.getConferenceCountry();
        if (!Locale.getISOCountries(Locale.IsoCountryCode.PART1_ALPHA2).contains(conferenceCountry)) {
            throw new BadRequestException("Invalid country code.");
        }

        String conferenceCity = request.getConferenceCity();
        String conferenceAddress = request.getConferenceAddress();
        String conferencePostalCode = request.getConferencePostalCode();

        if (!conferenceFrom.isAfter(LocalDate.now()) || conferenceTo.isBefore(conferenceFrom)) {
            throw new BadRequestException("Conference starts or ends too soon.");
        }

        if (conferenceRepository.existsByName(conferenceName) || conferenceRepository.existsByCodeName(conferenceCodeName)) {
            throw new BadRequestException("Duplicate conference.");
        }

        Conference conference = ConferenceHelper.create(conferenceName, conferenceCodeName, conferenceFrom,
            conferenceTo, conferenceCountry, conferenceCity, conferenceAddress, conferencePostalCode);

        for (CommitteeWithSeats committeeWithSeats : request.getCommitteeList()) {
            String committeeName = committeeWithSeats.getName();
            String committeeCodeName = committeeWithSeats.getCodeName();

            if (conference.getCommittees().removeIf(c -> c.getName().equals(committeeName) || c.getCodeName().equals(committeeCodeName))) {
                throw new BadRequestException("Duplicate committee.");
            }

            Committee committee = CommitteeHelper.create(committeeName, committeeCodeName);

            List<String> representedCountries = committeeWithSeats.getRepresentedCountries();
            for (String representedCountry : representedCountries) {
                if (!Locale.getISOCountries(Locale.IsoCountryCode.PART1_ALPHA2).contains(representedCountry)) {
                    throw new BadRequestException("Invalid country code.");
                }

                if (committee.getCommitteeSeats().removeIf(s -> s.getRepresentedCountry().equals(representedCountry))) {
                    throw new BadRequestException("Duplicate country.");
                }

                CommitteeSeat committeeSeat = CommitteeSeatHelper.create(representedCountry);
                committee.getCommitteeSeats().add(committeeSeat);
            }

            conference.getCommittees().add(committee);
        }

        UserIdentity userIdentity = authenticationService.getCurrentUserIdentity();
        conference.setOrganizer(userIdentity);

        conferenceRepository.save(conference);
    }

    public void cancelConferenceV1(CancelConferenceV1Request request) throws IOException {
        Conference conference = conferenceRepository.findById(request.getConferenceId(), 2)
            .orElseThrow(() -> new BadRequestException("Conference not found."));

        for (Committee committee : conference.getCommittees()) {
            for (CommitteeSeat committeeSeat : committee.getCommitteeSeats()) {
                emailSendingEngine.sendConferenceCancelledEmail(committeeSeat.getDelegate(), conference.getName());
            }

            committeeSeatRepository.deleteAll(committee.getCommitteeSeats());
        }

        committeeRepository.deleteAll(conference.getCommittees());
        conferenceRepository.delete(conference);
    }

    public void applyConferenceV1(ApplyConferenceV1Request request) {
        UserIdentity userIdentity =
            userIdentityRepository.findById(authenticationService.getCurrentUserIdentity().getId()).orElseThrow();
        CommitteeSeat committeeSeat = committeeSeatRepository.findById(request.getCommitteeSeatId(), 2)
            .orElseThrow(() -> new BadRequestException("Committee seat not found."));

        if (committeeSeat.getDelegate() != null) {
            throw new BadRequestException("Committee seat is already reserved.");
        }

        if (userIdentity.getConferences().contains(committeeSeat.getCommittee().getConference())) {
            throw new BadRequestException("Already applied to a committee seat on this conference.");
        }

        userIdentity.getCommitteeSeats().add(committeeSeat);
        userIdentity.getConferences().add(committeeSeat.getCommittee().getConference());

        userIdentityRepository.save(userIdentity);
    }

    public void cancelApplicationV1(CancelApplicationV1Request request) throws IOException {
        UserIdentity userIdentity =
            userIdentityRepository.findById(authenticationService.getCurrentUserIdentity().getId()).orElseThrow();
        CommitteeSeat committeeSeat = committeeSeatRepository.findById(request.getCommitteeSeatId(), 2)
            .orElseThrow(() -> new BadRequestException("Committee seat not found."));

        if (committeeSeat.getDelegate() == null) {
            throw new BadRequestException("Committee seat is empty.");
        }

        if (!committeeSeat.getDelegate().equals(userIdentity)) {
            throw new BadRequestException("Delegate did not apply to this committee seat.");
        }

        Committee committee = committeeSeat.getCommittee();
        Conference conference = committee.getConference();
        if (!userIdentity.getConferences().contains(conference)) {
            throw new InternalServerError("Delegate only assigned to committee seat, but not to conference.");
        }

        userIdentity.getCommitteeSeats().remove(committeeSeat);
        userIdentity.getConferences().remove(conference);

        userIdentityRepository.save(userIdentity);

        Locale locale = new Locale("", committeeSeat.getRepresentedCountry());
        emailSendingEngine.sendApplicationCancelledEmail(userIdentity, conference.getName(), committee.getName(),
            locale.getDisplayCountry());
    }

    public List<String> getMyConferencesV1() {
        UserIdentity userIdentity =
            userIdentityRepository.findById(authenticationService.getCurrentUserIdentity().getId()).orElseThrow();
        return userIdentity.getConferences().stream()
            .filter(c -> LocalDate.now().isBefore(c.getTo()))
            .map(AbstractIdentifiableNodeEntity::getId)
            .collect(Collectors.toList());
    }

    public List<String> getMyOrganizedConferencesV1() {
        UserIdentity userIdentity =
            userIdentityRepository.findById(authenticationService.getCurrentUserIdentity().getId()).orElseThrow();
        return userIdentity.getOrganizedConferences().stream()
            .filter(c -> LocalDate.now().isBefore(c.getTo()))
            .map(AbstractIdentifiableNodeEntity::getId)
            .collect(Collectors.toList());
    }
}
