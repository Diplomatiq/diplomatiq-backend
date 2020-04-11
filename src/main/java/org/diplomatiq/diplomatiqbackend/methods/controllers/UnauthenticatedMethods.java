package org.diplomatiq.diplomatiqbackend.methods.controllers;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UnauthenticatedMethods {

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
        name = "challengeV1",
        path = "challenge-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public void challengeV1() {
    }

}
