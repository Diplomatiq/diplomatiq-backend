package org.diplomatiq.diplomatiqbackend.methods.controllers.device;

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
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.GetSessionV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.GetSessionV1Response;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.validation.Valid;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Tag(name = "Device methods", description = "These methods are available with a logged-in device. Requests must be " +
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
    @SecurityRequirement(name = "Instant"),
    @SecurityRequirement(name = "SignedHeaders"),
})
@RestController
public class DeviceMethods {
    @Autowired
    private AuthenticationService authenticationService;

    @Operation(
        summary = "Get a session for calling API methods",
        description = "Creates a session for a device specified by the session token, and returns its encrypted ID. " +
            "If the caller device has a session which is still valid for at least 1 minute, it returns the old " +
            "session's encrypted ID."
    )
    @RequestMapping(
        name = "getSessionV1",
        path = "get-session-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public GetSessionV1Response getSessionV1(
        @Parameter(description = "The request body as a `GetSessionV1Request` object")
        @Valid
        @RequestBody
            GetSessionV1Request request
    ) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
        IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        return authenticationService.getSessionV1(request);
    }
}
