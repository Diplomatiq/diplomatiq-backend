package org.diplomatiq.diplomatiqbackend.methods.controllers;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UnauthenticatedMethods {

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
