package org.diplomatiq.diplomatiqbackend.configuration;

import com.sendgrid.SendGrid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SendGridConfiguration {
    @Value("${sendgrid.api-key}")
    private String SENDGRID_API_KEY;

    @Bean
    public SendGrid sendGridApiClient() {
        return new SendGrid(SENDGRID_API_KEY);
    }
}
