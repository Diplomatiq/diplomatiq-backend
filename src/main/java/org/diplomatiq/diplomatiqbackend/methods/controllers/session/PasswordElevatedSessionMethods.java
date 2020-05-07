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
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.ChangePasswordV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.ElevatePasswordElevatedSessionCompleteV1Request;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.io.IOException;

@Tag(name = "Session methods - PasswordElevatedSession", description = "These methods are available with a valid " +
    "session, with at least `PasswordElevatedSession` assurance level (the middle authentication assurance level). " +
    "Requests must be authenticated and signed according to the `SignedRequestV1` authentication scheme.")
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
@PreAuthorize("authenticatedBySessionWithAssuranceLevel('PasswordElevatedSession')")
public class PasswordElevatedSessionMethods {
    @Autowired
    private AuthenticationService authenticationService;

    @Operation(
        summary = "Initiate session elevation to MultiFactorElevatedSession assurance level",
        description = "Sends an email to the email address of the currently authenticated user with a multi-factor " +
            "authentication code."
    )
    @RequestMapping(
        name = "elevatePasswordElevatedSessionInitV1",
        path = "elevate-password-elevated-session-init-v1",
        method = RequestMethod.POST
    )
    public void elevatePasswordElevatedSessionInitV1() throws IOException {
        authenticationService.elevatePasswordElevatedSessionInitV1();
    }

    @Operation(
        summary = "Complete session elevation to MultiFactorElevatedSession assurance level",
        description = "Verifies a multi-factor authentication code previously sent to the user's email address. If " +
            "successful, the current session was elevated to `MultiFactorElevatedSession` assurance level."
    )
    @RequestMapping(
        name = "elevatePasswordElevatedSessionCompleteV1",
        path = "elevate-password-elevated-session-complete-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public void elevatePasswordElevatedSessionCompleteV1(
        @Parameter(description = "The request body as a `ElevatePasswordElevatedSessionCompleteV1Request` object")
        @Valid
        @RequestBody
            ElevatePasswordElevatedSessionCompleteV1Request request
    ) {
        authenticationService.elevatePasswordElevatedSessionCompleteV1(request);
    }

    @Operation(
        summary = "Change the user's password",
        description = "Changes the user's password to be able to authenticate with the new one."
    )
    @RequestMapping(
        name = "changePasswordV1",
        path = "change-password-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public void changePasswordV1(
        @Parameter(description = "The request body as a `ChangePasswordV1Request` object")
        @Valid
        @RequestBody
            ChangePasswordV1Request request
    ) {
        authenticationService.changePasswordV1(request);
    }
}
