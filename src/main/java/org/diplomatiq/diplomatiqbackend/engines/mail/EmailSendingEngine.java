package org.diplomatiq.diplomatiqbackend.engines.mail;

import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Email;
import com.sendgrid.helpers.mail.objects.Personalization;
import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.*;
import org.diplomatiq.diplomatiqbackend.repositories.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class EmailSendingEngine {
    private static final Email FROM_EMAIL;

    static {
        FROM_EMAIL = new Email();
        FROM_EMAIL.setName("The Diplomatiq Team");
        FROM_EMAIL.setEmail("team@diplomatiq.org");
    }

    private final Logger logger = LoggerFactory.getLogger(EmailSendingEngine.class);

    @Autowired
    SendGrid sendGridApiClient;

    @Autowired
    UserIdentityRepository userIdentityRepository;

    @Autowired
    UserAuthenticationRepository userAuthenticationRepository;

    @Autowired
    SessionRepository sessionRepository;

    @Autowired
    AuthenticationSessionRepository authenticationSessionRepository;

    @Autowired
    UserDeviceRepository userDeviceRepository;

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
                "https://app.diplomatiq.org/validate-email-address?email-address=%s&email-validation-key=%s",
                URLEncoder.encode(userIdentity.getEmailAddress(), StandardCharsets.UTF_8),
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

        sendRequest(request);
    }

    public void sendPasswordResetEmail(UserAuthenticationResetRequest userAuthenticationResetRequest) throws IOException {
        UserAuthentication userAuthentication = userAuthenticationRepository
            .findById(userAuthenticationResetRequest.getUserAuthentication().getId()).orElseThrow();
        UserIdentity userIdentity = userIdentityRepository.findById(userAuthentication.getUserIdentity().getId())
            .orElseThrow();

        Email toEmail = new Email();
        toEmail.setEmail(userIdentity.getEmailAddress());
        toEmail.setName(String.format("%s %s", userIdentity.getFirstName(), userIdentity.getLastName()));

        Personalization personalization = new Personalization();
        personalization.addTo(toEmail);

        personalization.addDynamicTemplateData("firstName", userIdentity.getFirstName());
        personalization.addDynamicTemplateData("lastName", userIdentity.getLastName());
        personalization.addDynamicTemplateData("passwordResetUrl",
            String.format(
                "https://app.diplomatiq.org/login?email-address=%s&password-reset-key=%s",
                URLEncoder.encode(userIdentity.getEmailAddress(), StandardCharsets.UTF_8),
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

        sendRequest(request);
    }

    public void sendMultiFactorAuthenticationEmail(SessionMultiFactorElevationRequest sessionMultiFactorElevationRequest) throws IOException {
        Session session =
            sessionRepository.findById(sessionMultiFactorElevationRequest.getSession().getId()).orElseThrow();
        UserDevice userDevice = userDeviceRepository.findById(session.getUserDevice().getId()).orElseThrow();

        sendMultiFactorAuthenticationEmailInternal(
            userDevice.getUserIdentity(),
            sessionMultiFactorElevationRequest.getRequestCode()
        );
    }

    public void sendMultiFactorAuthenticationEmail(AuthenticationSessionMultiFactorElevationRequest authenticationSessionMultiFactorElevationRequest) throws IOException {
        AuthenticationSession authenticationSession = authenticationSessionRepository
            .findById(authenticationSessionMultiFactorElevationRequest.getAuthenticationSession().getId())
            .orElseThrow();
        UserAuthentication userAuthentication = userAuthenticationRepository
            .findById(authenticationSession.getUserAuthentication().getId()).orElseThrow();

        sendMultiFactorAuthenticationEmailInternal(
            userAuthentication.getUserIdentity(),
            authenticationSessionMultiFactorElevationRequest.getRequestCode()
        );
    }

    public void sendAccountDeletionEmail(String emailAddress, String firstName, String lastName) throws IOException {
        Email toEmail = new Email();
        toEmail.setEmail(emailAddress);
        toEmail.setName(String.format("%s %s", firstName, lastName));

        Personalization personalization = new Personalization();
        personalization.addTo(toEmail);

        personalization.addDynamicTemplateData("firstName", firstName);
        personalization.addDynamicTemplateData("lastName", lastName);

        Mail mail = new Mail();
        mail.setFrom(FROM_EMAIL);
        mail.setReplyTo(FROM_EMAIL);
        mail.setTemplateId("d-07803756f7e2425b851e0041a455c5d0");
        mail.addPersonalization(personalization);

        Request request = new Request();
        request.setMethod(Method.POST);
        request.setEndpoint("mail/send");
        request.setBody(mail.build());

        sendRequest(request);
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

        sendRequest(request);
    }

    private void sendRequest(Request request) throws IOException {
        Response response = sendGridApiClient.api(request);
        if (response != null) {
            HttpStatus responseCode = HttpStatus.valueOf(response.getStatusCode());
            if (responseCode.isError()) {
                logger.warn("Could not send email: {}", response.getBody());
            }
        }
    }
}
