package org.diplomatiq.diplomatiqbackend.methods.controllers.unauthenticated;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.diplomatiq.diplomatiqbackend.exceptions.DiplomatiqApiError;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.PasswordAuthenticationCompleteV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.PasswordAuthenticationInitV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.requests.RegisterUserV1Request;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationCompleteV1Response;
import org.diplomatiq.diplomatiqbackend.methods.entities.responses.PasswordAuthenticationInitV1Response;
import org.diplomatiq.diplomatiqbackend.services.AuthenticationService;
import org.diplomatiq.diplomatiqbackend.services.RegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.security.NoSuchAlgorithmException;

@Tag(name = "Unauthenticated methods", description = "These methods are available without authentication and request " +
    "signing.")
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
@RestController
public class UnauthenticatedMethods {
    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private AuthenticationService authenticationService;

    @Operation(
        summary = "Get the key of a device container",
        description = "Returns the key of the device container with the given ID."
    )
    @RequestMapping(
        name = "getDeviceContainerKeyV1",
        path = "get-device-container-key-v1",
        method = RequestMethod.GET,
        produces = MediaType.APPLICATION_OCTET_STREAM_VALUE
    )
    public byte[] getDeviceContainerKeyV1(
        @Parameter(description = "The ID of the user's device")
        @NotBlank
        @RequestParam
            String deviceId
    ) {
        return authenticationService.getDeviceContainerKeyV1(deviceId);
    }

    @Operation(
        summary = "Complete password authentication",
        description = "Completes an authentication flow for the given email address, based on the Secure Remote " +
            "Password protocol (version 6a). Returns the resulting authentication session's ID encrypted with the " +
            "session key the client and the server mutually agreed on."
    )
    @RequestMapping(
        name = "passwordAuthenticationCompleteV1",
        path = "password-authentication-complete-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public PasswordAuthenticationCompleteV1Response passwordAuthenticationCompleteV1(
        @Parameter(description = "The request body as a `PasswordAuthenticationCompleteV1Request` object")
        @Valid
        @RequestBody
            PasswordAuthenticationCompleteV1Request request
    ) {
        return authenticationService.passwordAuthenticationCompleteV1(request);
    }

    @Operation(
        summary = "Initiate password authentication",
        description = "Initiates the authentication flow for the given email address, based on the Secure Remote " +
            "Password protocol (version 6a)."
    )
    @RequestMapping(
        name = "passwordAuthenticationInitV1",
        path = "password-authentication-init-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public PasswordAuthenticationInitV1Response passwordAuthenticationInitV1(
        @Parameter(description = "The request body as a `PasswordAuthenticationInitV1Request` object")
        @Valid
        @RequestBody
            PasswordAuthenticationInitV1Request request) {
        return authenticationService.passwordAuthenticationInitV1(request);
    }

    @Operation(
        summary = "Register a user",
        description = "Registers a user identified by the given email address. The email address is converted to its " +
            "lowercase invariant, and is stored that way!"
    )
    @RequestMapping(
        name = "registerUserV1",
        path = "register-user-v1",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public void registerUserV1(
        @Parameter(description = "The request body as a `RegisterUserV1Request` object")
        @Valid
        @RequestBody
            RegisterUserV1Request request) throws NoSuchAlgorithmException {
        registrationService.registerUser(request);
    }

    @Operation(
        summary = "Validate the email address of a user",
        description = "Sets the corresponding user's email address to validated"
    )
    @RequestMapping(
        name = "validateEmailAddressV1",
        path = "validate-email-address-v1",
        method = RequestMethod.GET
    )
    public void validateEmailAddressV1(
        @Parameter(description = "The ID of the user's device")
        @NotBlank
        @RequestParam
            String emailValidationKey
    ) {
        authenticationService.validateEmailAddressV1(emailValidationKey);
    }
}
