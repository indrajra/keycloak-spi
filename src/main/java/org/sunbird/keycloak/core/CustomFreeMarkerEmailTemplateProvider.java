package org.sunbird.keycloak.core;

import org.jboss.logging.Logger;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.email.freemarker.FreeMarkerEmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.theme.FreeMarkerUtil;

import java.util.Map;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class CustomFreeMarkerEmailTemplateProvider extends FreeMarkerEmailTemplateProvider implements EmailTemplateProvider {
    private static final Logger logger = Logger.getLogger(CustomFreeMarkerEmailTemplateProvider.class);

    public CustomFreeMarkerEmailTemplateProvider(KeycloakSession session, FreeMarkerUtil freeMarker) {
        super(session, freeMarker);
        logger.info("CustomFreeMarkerEmailTemplateProvider instantiated");
    }

    protected void send(Map<String, String> config, String subject, String textBody, String htmlBody) throws EmailException
    {
        logger.info("Send from CustomFreeMarkerEmailTemplate");
        EmailSenderProvider emailSender = session.getProvider(EmailSenderProvider.class, "spi-email-sender");
        emailSender.send(config, user, subject, textBody, htmlBody);
    }
}
