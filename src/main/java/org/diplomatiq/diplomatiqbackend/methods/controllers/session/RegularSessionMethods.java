package org.diplomatiq.diplomatiqbackend.methods.controllers.session;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiError;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.ApplyConferenceV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.ElevateRegularSessionCompleteV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.OrganizeConferenceV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.ElevateRegularSessionInitV1Response;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.GetUserIdentityV1Response;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.diplomatiq.diplomatiqbackend.services.ConferenceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.List;

@Tag(name = "Session methods - RegularSession", description = "These methods are available with a valid session, with" +
    "at least `RegularSession` assurance level (the lowest authentication assurance level). Requests must be " +
    "authenticated and signed according to the `SessionSignatureV1` authentication scheme.")
@ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "The operation was successful."
    ),
    @ApiResponse(
        responseCode = "400",
        description = "An error happened. See the `errorCode` and the optional `retryInformation` fields of the " +
            "response.",
        content = @Content(
            mediaType = MediaType.APPLICATION_JSON_VALUE,
            schema = @Schema(implementation = DiplomatiqApiError.class)
        )
    )
})
@SecurityRequirements({
    @SecurityRequirement(name = "Authorization"),
    @SecurityRequirement(name = "ClientId"),
    @SecurityRequirement(name = "DeviceId"),
    @SecurityRequirement(name = "Instant"),
    @SecurityRequirement(name = "SessionId"),
    @SecurityRequirement(name = "SignedHeaders"),
})
@RestController
@PreAuthorize("authenticatedBySessionWithAssuranceLevel('RegularSession')")
public class RegularSessionMethods {
    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private ConferenceService conferenceService;

    @Operation(
        summary = "Apply to a conference, to the specified committee place",
        description = "Registers a user application to the specified committee place of a conference."
    )
    @RequestMapping(
        name = "applyConferenceV1",
        path = "apply-conference-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public void applyConferenceV1(
        @Parameter(description = "The request body as a `ApplyConferenceV1Request` object")
        @Valid
        @RequestBody
            ApplyConferenceV1Request request) {
        conferenceService.applyConferenceV1(request);
    }

    @Operation(
        summary = "Complete session elevation to PasswordElevatedSession assurance level",
        description = "Completes an authentication flow for the given email address, based on the Secure Remote " +
            "Password protocol (version 6a). If successful, the current session was elevated to " +
            "`PasswordElevatedSession` " +
            "assurance level."
    )
    @RequestMapping(
        name = "elevateRegularSessionCompleteV1",
        path = "elevate-regular-session-complete-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public void elevateRegularSessionCompleteV1(
        @Parameter(description = "The request body as a `ElevateRegularSessionCompleteV1Request` object")
        @Valid
        @RequestBody
            ElevateRegularSessionCompleteV1Request request) {
        authenticationService.elevateRegularSessionCompleteV1(request);
    }

    @Operation(
        summary = "Initiate session elevation to PasswordElevatedSession assurance level",
        description = "Initiates the authentication flow for the current user, based on the Secure Remote Password " +
            "protocol (version 6a)."
    )
    @RequestMapping(
        name = "elevateRegularSessionInitV1",
        path = "elevate-regular-session-init-v1",
        method = RequestMethod.POST,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ElevateRegularSessionInitV1Response elevateRegularSessionInitV1() {
        return authenticationService.elevateRegularSessionInitV1();
    }

    @Operation(
        summary = "Get the conferences which the user participates in",
        description = "Returns the ids of conferences which the user participates in (not organizes)."
    )
    @RequestMapping(
        name = "getMyConferences",
        path = "get-my-conferences-v1",
        method = RequestMethod.GET,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public List<String> getMyConferencesV1() {
        return conferenceService.getMyConferencesV1();
    }

    @Operation(
        summary = "Get the conferences which are organized by the user",
        description = "Returns the ids of conferences which the user organizes (not participates in)."
    )
    @RequestMapping(
        name = "getMyOrganizedConferences",
        path = "get-my-organized-conferences-v1",
        method = RequestMethod.GET,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public List<String> getMyOrganizedConferencesV1() {
        return conferenceService.getMyOrganizedConferencesV1();
    }

    @Operation(
        summary = "Create a conference in the system with committees and commitee seats",
        description = "Creates a conference with the given committees and the corresponding committee seats, which " +
            "delegates can apply on."
    )
    @RequestMapping(
        name = "organizeConferenceV1",
        path = "organize-conference-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public void organizeConferenceV1(
        @Parameter(description = "The request body as a `OrganizeConferenceV1Request` object")
        @Valid
        @RequestBody
            OrganizeConferenceV1Request request
    ) {
        conferenceService.organizeConferenceV1(request);
    }

    @Operation(
        summary = "Get the identity of the user",
        description = "Returns the identity of the authenticated user"
    )
    @RequestMapping(
        name = "getUserIdentityV1",
        path = "get-user-identity-v1",
        method = RequestMethod.GET,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public GetUserIdentityV1Response getUserIdentityV1() {
        return authenticationService.getUserIdentityV1();
    }
}
