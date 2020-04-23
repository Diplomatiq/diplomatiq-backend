package org.diplomatiq.diplomatiqbackend.engines.mail;

import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Email;
import com.sendgrid.helpers.mail.objects.Personalization;
import org.diplomatiq.diplomatiqbackend.configuration.SendGridConfiguration;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserIdentity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class EmailSendingEngine {
    private static final Email FROM_EMAIL;

    static {
        FROM_EMAIL = new Email();
        FROM_EMAIL.setName("The Diplomatiq Team");
        FROM_EMAIL.setEmail("team@diplomatiq.org");
    }

    @Autowired
    SendGridConfiguration sendGridConfiguration;

    public void sendEmailAddressValidationEmail(UserIdentity userIdentity) throws IOException {
        Email toEmail = new Email();
        toEmail.setEmail(userIdentity.getEmailAddress());
        toEmail.setName(String.format("%s %s", userIdentity.getFirstName(), userIdentity.getLastName()));

        Personalization personalization = new Personalization();
        personalization.addTo(toEmail);

        personalization.addDynamicTemplateData("firstName", userIdentity.getFirstName());
        personalization.addDynamicTemplateData("lastName", userIdentity.getLastName());
        personalization.addDynamicTemplateData("emailAddressValidationUrl",
            String.format(
                "https://app.diplomatiq.org/validate-email-address?email-validation-key=%s",
                userIdentity.getEmailValidationKey()
            )
        );

        Mail mail = new Mail();
        mail.setFrom(FROM_EMAIL);
        mail.setReplyTo(FROM_EMAIL);
        mail.setTemplateId("d-529b51154b51430aba9d0cbefbdde393");
        mail.addPersonalization(personalization);

        Request request = new Request();
        request.setMethod(Method.POST);
        request.setEndpoint("mail/send");
        request.setBody(mail.build());

        SendGrid sendGrid = sendGridConfiguration.sendGridApiClient();
        sendGrid.api(request);
    }
}
