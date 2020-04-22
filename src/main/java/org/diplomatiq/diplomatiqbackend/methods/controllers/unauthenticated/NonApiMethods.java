package org.diplomatiq.diplomatiqbackend.methods.controllers.unauthenticated;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Non-API methods", description = "These methods are not real API methods.")
@RestController
public class NonApiMethods {
    @Operation(
        summary = "Redirect to www.diplomatiq.org",
        description = "This endpoint issues a temporary redirect (HTTP 307) to [https://www.diplomatiq.org]" +
            "(https://www.diplomatiq.org)."
    )
    @ApiResponse(
        description = "Issued a redirect to [https://www.diplomatiq.org](https://www.diplomatiq.org).",
        responseCode = "307",
        headers = {
            @Header(
                name = "Location",
                description = "Specifies the target of the redirection, which is [https://www.diplomatiq.org]" +
                    "(https://www.diplomatiq.org).",
                schema = @Schema(type = "string")
            )
        }
    )
    @RequestMapping(
        name = "rootRedirect",
        path = "",
        method = RequestMethod.GET
    )
    public ResponseEntity<Void> rootRedirect() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Location", "https://www.diplomatiq.org");
        return new ResponseEntity<>(headers, HttpStatus.TEMPORARY_REDIRECT);
    }
}
