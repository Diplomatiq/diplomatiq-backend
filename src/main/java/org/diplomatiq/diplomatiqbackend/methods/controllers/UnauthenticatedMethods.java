package org.diplomatiq.diplomatiqbackend.methods.controllers;

import org.diplomatiq.diplomatiqbackend.methods.entities.requests.PasswordAuthenticationCompleteV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.PasswordAuthenticationInitV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.RegisterUserV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationCompleteV1Response;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationInitV1Response;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.diplomatiq.diplomatiqbackend.services.RegistrationService;
import org.diplomatiq.diplomatiqbackend.services.UserIdentityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.security.NoSuchAlgorithmException;

@RestController
public class UnauthenticatedMethods {
    @Autowired
    private UserIdentityService userIdentityService;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private AuthenticationService authenticationService;

    @RequestMapping(
        name = "rootRedirect",
        path = "",
        method = RequestMethod.GET
    )
    public ResponseEntity rootRedirect() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Location", "https://www.diplomatiq.org");
        return new ResponseEntity<>(headers, HttpStatus.TEMPORARY_REDIRECT);
    }

    @RequestMapping(
        name = "registerUserV1",
        path = "register-user-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public void registerUserV1(@Valid @RequestBody RegisterUserV1Request request) {
        registrationService.registerUser(request);
    }

    @RequestMapping(
        name = "getDeviceContainerKey",
        path = "get-device-container-key-v1",
        method = RequestMethod.GET,
        produces = MediaType.APPLICATION_OCTET_STREAM_VALUE
    )
    public byte[] getDeviceContainerKeyV1(@NotBlank @RequestParam String deviceContainerId) {
        return authenticationService.getDeviceContainerKeyV1(deviceContainerId);
    }

    @RequestMapping(
        name = "passwordAuthenticationInitV1",
        path = "password-authentication-init-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public PasswordAuthenticationInitV1Response passwordAuthenticationInitV1(@Valid @RequestBody PasswordAuthenticationInitV1Request request) {
        return authenticationService.passwordAuthenticationInitV1(request);
    }

    @RequestMapping(
        name = "passwordAuthenticationCompleteV1",
        path = "password-authentication-complete-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public PasswordAuthenticationCompleteV1Response passwordAuthenticationCompleteV1(@Valid @RequestBody PasswordAuthenticationCompleteV1Request request) throws NoSuchAlgorithmException {
        return authenticationService.passwordAuthenticationCompleteV1(request);
    }

}
