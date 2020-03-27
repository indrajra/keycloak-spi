package org.sunbird.keycloak.core;

import org.keycloak.Config;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.email.EmailSenderProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class CustomEmailSenderProviderFactory implements EmailSenderProviderFactory {
    private final String PROVIDER = "spi-email-sender";
    @Override
    public EmailSenderProvider create(KeycloakSession session) {
        return new CustomEmailSenderProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER;
    }

}
