package org.diplomatiq.diplomatiqbackend.methods.controllers.session;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiError;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Session methods - RegularSession", description = "These methods are available with a valid session, with" +
    "at least `RegularSession` assurance level (the lowest authentication assurance level). Requests must be " +
    "authenticated and signed according to the `SignedRequestV1` authentication scheme.")
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
public class RegularSessionMethods {
    @Autowired
    private AuthenticationService authenticationService;

    @Operation(
        summary = "Log out from a device",
        description = "Logs out the user on the current client device. Deregisters the client device and its session," +
            " and revokes request signing and authentication credentials for that client device."
    )
    @RequestMapping(
        name = "logoutV1",
        path = "logout-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public void logoutV1() {
        authenticationService.logoutV1();
    }
}
