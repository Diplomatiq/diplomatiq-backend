package org.diplomatiq.diplomatiqbackend.configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.diplomatiq.diplomatiqbackend.filters.signature.DiplomatiqHeaders;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
public class OpenAPIConfiguration {
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(
                new Info()
                    .title("Diplomatiq API")
                    .description("This is the OpenAPI of the Diplomatiq API.")
            ).servers(
                List.of(
                    new Server()
                        .url("https://api.diplomatiq.org")
                        .description("Production server"),
                    new Server()
                        .url("https://api.diplomatiq.org?x-ms-routing-name=staging")
                        .description("Staging server - ONLY FOR TESTING!"),
                    new Server()
                        .url("https://api.diplomatiq.org?x-ms-routing-name=develop")
                        .description("Develop server - ONLY FOR TESTING!")
                )
            ).components(
                new Components()
                    .securitySchemes(
                        DiplomatiqHeaders.AllRequiredHeadersWithDescription.entrySet().stream().collect(
                            Collectors.toMap(
                                Map.Entry::getKey,
                                entry -> new SecurityScheme()
                                    .type(SecurityScheme.Type.APIKEY)
                                    .in(SecurityScheme.In.HEADER)
                                    .name(entry.getKey())
                                    .description(entry.getValue())
                            )
                        )
                    )
            );
    }
}
