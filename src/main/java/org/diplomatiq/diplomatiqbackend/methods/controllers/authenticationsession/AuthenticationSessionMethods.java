package org.diplomatiq.diplomatiqbackend.methods.controllers.authenticationsession;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiError;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.LoginV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.LoginV1Response;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.validation.Valid;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Tag(name = "Authentication session methods", description = "These methods are available with an authentication " +
    "session. Requests must be authenticated and signed according to the `SignedAuthenticationSessionV1` " +
    "authentication scheme.")
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
public class AuthenticationSessionMethods {
    @Autowired
    private AuthenticationService authenticationService;

    @Operation(
        summary = "Log in from a device",
        description = "Registers a client device, and issues request signing and authentication credentials for that " +
            "client device."
    )
    @RequestMapping(
        name = "loginV1",
        path = "login-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public LoginV1Response loginV1(
        @Parameter(description = "The request body as a `LoginV1Request` object")
        @Valid
        @RequestBody
            LoginV1Request request
    ) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        return authenticationService.loginV1(request);
    }
}
