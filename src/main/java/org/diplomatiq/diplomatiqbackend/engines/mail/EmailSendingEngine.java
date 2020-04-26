package org.diplomatiq.diplomatiqbackend.engines.mail;

import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Email;
import com.sendgrid.helpers.mail.objects.Personalization;
import org.diplomatiq.diplomatiqbackend.configuration.SendGridConfiguration;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.AuthenticationSessionMultiFactorElevationRequest;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.SessionMultiFactorElevationRequest;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserAuthenticationResetRequest;
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

    public void sendPasswordResetEmail(UserAuthenticationResetRequest userAuthenticationResetRequest) throws IOException {
        UserIdentity userIdentity = userAuthenticationResetRequest.getUserAuthentication().getUserIdentity();

        Email toEmail = new Email();
        toEmail.setEmail(userIdentity.getEmailAddress());
        toEmail.setName(String.format("%s %s", userIdentity.getFirstName(), userIdentity.getLastName()));

        Personalization personalization = new Personalization();
        personalization.addTo(toEmail);

        personalization.addDynamicTemplateData("firstName", userIdentity.getFirstName());
        personalization.addDynamicTemplateData("lastName", userIdentity.getLastName());
        personalization.addDynamicTemplateData("passwordResetUrl",
            String.format(
                "https://app.diplomatiq.org/reset-password?password-reset-key=%s",
                userAuthenticationResetRequest.getRequestKey()
            )
        );

        Mail mail = new Mail();
        mail.setFrom(FROM_EMAIL);
        mail.setReplyTo(FROM_EMAIL);
        mail.setTemplateId("d-6f985ba956f34641a1e5f230d7d65b48");
        mail.addPersonalization(personalization);

        Request request = new Request();
        request.setMethod(Method.POST);
        request.setEndpoint("mail/send");
        request.setBody(mail.build());

        SendGrid sendGrid = sendGridConfiguration.sendGridApiClient();
        sendGrid.api(request);
    }

    public void sendMultiFactorAuthenticationEmail(SessionMultiFactorElevationRequest sessionMultiFactorElevationRequest) throws IOException {
        sendMultiFactorAuthenticationEmailInternal(
            sessionMultiFactorElevationRequest.getSession().getUserDevice().getUserIdentity(),
            sessionMultiFactorElevationRequest.getRequestCode()
        );
    }

    public void sendMultiFactorAuthenticationEmail(AuthenticationSessionMultiFactorElevationRequest authenticationSessionMultiFactorElevationRequest) throws IOException {
        sendMultiFactorAuthenticationEmailInternal(
            authenticationSessionMultiFactorElevationRequest.getAuthenticationSession().getUserAuthentication().getUserIdentity(),
            authenticationSessionMultiFactorElevationRequest.getRequestCode()
        );
    }

    private void sendMultiFactorAuthenticationEmailInternal(UserIdentity userIdentity, String authenticationCode) throws IOException {
        Email toEmail = new Email();
        toEmail.setEmail(userIdentity.getEmailAddress());
        toEmail.setName(String.format("%s %s", userIdentity.getFirstName(), userIdentity.getLastName()));

        Personalization personalization = new Personalization();
        personalization.addTo(toEmail);

        personalization.addDynamicTemplateData("firstName", userIdentity.getFirstName());
        personalization.addDynamicTemplateData("lastName", userIdentity.getLastName());
        personalization.addDynamicTemplateData("authenticationCode", authenticationCode);

        Mail mail = new Mail();
        mail.setFrom(FROM_EMAIL);
        mail.setReplyTo(FROM_EMAIL);
        mail.setTemplateId("d-44cc52b74ef94f798e0d1837f97574d0");
        mail.addPersonalization(personalization);

        Request request = new Request();
        request.setMethod(Method.POST);
        request.setEndpoint("mail/send");
        request.setBody(mail.build());

        SendGrid sendGrid = sendGridConfiguration.sendGridApiClient();
        sendGrid.api(request);
    }
}
