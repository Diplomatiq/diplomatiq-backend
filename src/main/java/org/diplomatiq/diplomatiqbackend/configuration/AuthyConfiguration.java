package org.diplomatiq.diplomatiqbackend.configuration;

import com.authy.AuthyApiClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthyConfiguration {
    @Value("${AUTHY_API_KEY:authy}")
    private String AUTHY_API_KEY;

    @Bean
    public AuthyApiClient authyApiClient() {
        return new AuthyApiClient(AUTHY_API_KEY);
    }
}
