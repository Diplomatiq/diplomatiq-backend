package org.diplomatiq.diplomatiqbackend.configuration;

import com.sendgrid.SendGrid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SendGridConfiguration {
    @Value("${SENDGRID_API_KEY:sendgrid}")
    private String SENDGRID_API_KEY;

    public SendGrid sendGridApiClient() {
        return new SendGrid(SENDGRID_API_KEY);
    }
}
