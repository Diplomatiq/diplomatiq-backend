package org.diplomatiq.diplomatiqbackend.methods.controllers.authenticationsession;

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
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.ElevateAuthenticationSessionCompleteV1Request;
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

@Tag(
    name = "Authentication session methods - PasswordElevatedSession",
    description = "These methods are available with an authentication session, with at least " +
        "`PasswordElevatedSession` assurance level. Requests must be authenticated and signed according to the " +
        "`AuthenticationSessionSignatureV1` authentication scheme."
)
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
    @SecurityRequirement(name = "AuthenticationSessionId"),
    @SecurityRequirement(name = "Authorization"),
    @SecurityRequirement(name = "ClientId"),
    @SecurityRequirement(name = "Instant"),
    @SecurityRequirement(name = "SignedHeaders"),
})
@RestController
@PreAuthorize("authenticatedByAuthenticationSessionWithAssuranceLevel('PasswordElevatedSession')")
public class PasswordElevatedAuthenticationSessionMethods {
    @Autowired
    private AuthenticationService authenticationService;

    @Operation(
        summary = "Initiate authentication session elevation to MultiFactorElevatedSession assurance level",
        description = "Sends an email to the email address of the currently authenticated user with a multi-factor " +
            "authentication code."
    )
    @RequestMapping(
        name = "elevateAuthenticationSessionInitV1",
        path = "elevate-authentication-session-init-v1",
        method = RequestMethod.POST
    )
    public void elevateAuthenticationSessionInitV1() throws IOException {
        authenticationService.elevateAuthenticationSessionInitV1();
    }

    @Operation(
        summary = "Complete authentication session elevation to MultiFactorElevatedSession assurance level",
        description = "Verifies a multi-factor authentication code previously sent to the user's email address. If " +
            "successful, the current authentication session was elevated to `MultiFactorElevatedSession` assurance " +
            "level."
    )
    @RequestMapping(
        name = "elevateAuthenticationSessionCompleteV1",
        path = "elevate-authentication-session-complete-v1",
        method = RequestMethod.POST
    )
    public void elevateAuthenticationSessionCompleteV1(
        @Parameter(description = "The request body as a `ElevateAuthenticationSessionCompleteV1Request` object")
        @Valid
        @RequestBody
            ElevateAuthenticationSessionCompleteV1Request request
    ) {
        authenticationService.elevateAuthenticationSessionCompleteV1(request);
    }
}
