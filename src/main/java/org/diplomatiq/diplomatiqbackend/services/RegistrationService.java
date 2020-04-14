package org.diplomatiq.diplomatiqbackend.services;

import org.diplomatiq.diplomatiqbackend.exceptions.api.InvalidSrpSaltException;
import org.diplomatiq.diplomatiqbackend.exceptions.api.InvalidSrpVerifierException;
import org.diplomatiq.diplomatiqbackend.methods.entities.RegisterUserV1Request;
import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;

@Service
@Transactional
public class RegistrationService {

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    public void registerUser(RegisterUserV1Request request) {
        byte[] srpSalt;
        try {
            srpSalt = Base64.getDecoder().decode(request.getSrpSaltHex());
        } catch (Exception ex) {
            throw new InvalidSrpSaltException("SRP salt could not be decoded.", ex);
        }

        byte[] srpVerifier;
        try {
            srpVerifier = Base64.getDecoder().decode(request.getSrpSaltHex());
        } catch (Exception ex) {
            throw new InvalidSrpVerifierException("SRP verifier could not be decoded.", ex);
        }

//        userIdentityRepository.save();
    }

}
