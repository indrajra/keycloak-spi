package org.sunbird.keycloak.core;


import org.jboss.logging.Logger;
import org.keycloak.authentication.ConsoleDisplayMode;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.RandomString;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilderException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class CustomConsoleVerifyEmail implements RequiredActionProvider {
    public static final CustomConsoleVerifyEmail SINGLETON = new CustomConsoleVerifyEmail();
    private static final Logger logger = Logger.getLogger(CustomConsoleVerifyEmail.class);

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        if (!context.getUser().isEmailVerified()) {
            logger.debug("Custom User is required to verify email");
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if (context.getUser().isEmailVerified()) {
            context.success();
            authSession.removeAuthNote(Constants.VERIFY_EMAIL_KEY);
            return;
        }

        String email = context.getUser().getEmail();
        if (Validation.isBlank(email)) {
            context.ignore();
            return;
        }

        Response challenge = sendVerifyEmail(context);
        context.challenge(challenge);
    }


    @Override
    public void processAction(RequiredActionContext context) {
        logger.info("Processing action");
        EventBuilder event = context.getEvent().clone().event(EventType.VERIFY_EMAIL).detail(Details.EMAIL, context.getUser().getEmail());
        String code = context.getAuthenticationSession().getAuthNote(Constants.VERIFY_EMAIL_CODE);
        if (code == null) {
            requiredActionChallenge(context);
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String emailCode = formData.getFirst(EMAIL_CODE);

        if (!code.equals(emailCode)) {
            context.challenge(
                    challenge(context).message(Messages.INVALID_CODE)
            );
            event.error(Errors.INVALID_CODE);
            return;
        }
        event.success();
        context.success();
    }


    @Override
    public void close() {

    }

    public static String EMAIL_CODE = "email_code";

    protected ConsoleDisplayMode challenge(RequiredActionContext context) {
        return ConsoleDisplayMode.challenge(context)
                .header()
                .param(EMAIL_CODE)
                .label("console-email-code")
                .challenge();
    }

    private Response sendVerifyEmail(RequiredActionContext context) throws UriBuilderException, IllegalArgumentException {
        logger.info("SendVerifyEmail");
        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        EventBuilder event = context.getEvent().clone().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL, user.getEmail());
        String code = RandomString.randomCode(8);
        authSession.setAuthNote(Constants.VERIFY_EMAIL_CODE, code);
        RealmModel realm = session.getContext().getRealm();

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("code", code);

        try {
            session
                    .getProvider(EmailTemplateProvider.class)
                    .setAuthenticationSession(authSession)
                    .setRealm(realm)
                    .setUser(user)
                    .send("emailVerificationSubject", "email-verification-with-code.ftl", attributes);
            event.success();
        } catch (EmailException e) {
            logger.error("Failed to send verification email", e);
            event.error(Errors.EMAIL_SEND_FAILED);
        }

        return challenge(context).text(context.form().getMessage("console-verify-email", user.getEmail()));
    }
}
