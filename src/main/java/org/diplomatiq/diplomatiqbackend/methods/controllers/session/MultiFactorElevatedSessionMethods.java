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
import org.diplomatiq.diplomatiqbackend.services.AccountDeletionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@Tag(name = "Session methods - MultiFactorElevatedSession", description = "These methods are available with a valid " +
    "session, with at least `MultiFactorElevatedSession` assurance level (the highest authentication assurance level)" +
    ". Requests must be authenticated and signed according to the `SignedRequestV1` authentication scheme.")
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
@PreAuthorize("authenticatedBySessionWithAssuranceLevel('MultiFactorElevatedSession')")
public class MultiFactorElevatedSessionMethods {
    @Autowired
    private AccountDeletionService accountDeletionService;

    @Operation(
        summary = "Delete the user's account",
        description = "Deletes the account of the user with all associated data in the system."
    )
    @RequestMapping(
        name = "deleteUserAccountV1",
        path = "delete-user-account-v1",
        method = RequestMethod.POST
    )
    public void deleteUserAccountV1(
    ) throws IOException {
        accountDeletionService.deleteUserAccountV1();
    }
}
