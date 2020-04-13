package org.diplomatiq.diplomatiqbackend.methods.controllers;

import org.diplomatiq.diplomatiqbackend.services.UserIdentityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UnauthenticatedMethods {

    @Autowired
    private UserIdentityService userIdentityService;

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
        name = "getChallengeV1",
        path = "get-challenge-v1",
        method = RequestMethod.POST,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public void getChallengeV1() {
    }

    @RequestMapping(
        name = "getDeviceContainerKey",
        path = "get-device-container-key-v1",
        method = RequestMethod.GET,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public void getDeviceContainerKeyV1() {
    }

}
