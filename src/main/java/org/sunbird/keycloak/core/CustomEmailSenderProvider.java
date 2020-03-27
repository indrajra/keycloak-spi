package org.sunbird.keycloak.core;

import org.jboss.logging.Logger;
import org.keycloak.email.DefaultEmailSenderProvider;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

import java.io.IOException;

public class CustomEmailSenderProvider extends DefaultEmailSenderProvider implements EmailSenderProvider {

    private static final Logger logger = Logger.getLogger(CustomEmailSenderProvider.class);

    private final KeycloakSession session;

    public CustomEmailSenderProvider(KeycloakSession session) {
        super(session);
        this.session = session;
        logger.info("CustomEmailSenderProvider instantiated");
    }

    protected String retrieveEmailAddress(UserModel user) {
        logger.info("RetrieveEmailAddressCalled");
        String email = null;
        try {
            email = EncryptionSevice.instance().decrypt(user.getEmail());
        } catch (IOException e) {
            logger.error("Can't decrypt users email", e);
            email = user.getEmail();
        }
        logger.info("Returning " + email);
        return email;
    }
}