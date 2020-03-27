package org.sunbird.keycloak.core;

/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.DisplayTypeRequiredActionFactory;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.actiontoken.verifyemail.VerifyEmailActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.services.Urls;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.FreeMarkerUtil;
import org.sunbird.keycloak.SPIConstants;

import javax.validation.constraints.Email;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriBuilderException;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.util.EnumMap;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class CustomVerifyEmail implements RequiredActionProvider, RequiredActionFactory, DisplayTypeRequiredActionFactory {
    private static final Logger logger = Logger.getLogger(CustomVerifyEmail.class);

    public static final String PROVIDER_ID = "CustomVerifyEmail";
    public static final CustomVerifyEmail SINGLETON = new CustomVerifyEmail();

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        logger.info("CustomVerifyEmail created");
        return SINGLETON;
    }


    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        if (!context.getUser().isEmailVerified()) {
            logger.info("Custom Verify Email User is required to verify email");
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

        String plainTextEmail = null;
        try {
            plainTextEmail = EncryptionSevice.instance().decrypt(context.getUser().getEmail());
        } catch (IOException e) {
            logger.error("SPI Cannot decrypt the email");
            context.ignore();
            return;
        }

        if (Validation.isBlank(plainTextEmail)) {
            context.ignore();
            return;
        }

        LoginFormsProvider loginFormsProvider = context.form();
        Response challenge;

        // Do not allow resending e-mail by simple page refresh, i.e. when e-mail sent, it should be resent properly via email-verification endpoint
        if (!Objects.equals(authSession.getAuthNote(Constants.VERIFY_EMAIL_KEY), plainTextEmail)) {
            authSession.setAuthNote(Constants.VERIFY_EMAIL_KEY, plainTextEmail);
            EventBuilder event = context.getEvent().clone().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL, plainTextEmail);
            challenge = sendVerifyEmail(context.getSession(), loginFormsProvider, context.getUser(),
                    context.getAuthenticationSession(), event);
        } else {
            challenge = loginFormsProvider.createResponse(UserModel.RequiredAction.VERIFY_EMAIL);
        }

        context.challenge(challenge);
    }


    @Override
    public void processAction(RequiredActionContext context) {
        logger.infof("SPI Re-sending email requested for user: %s", context.getUser().getUsername());

        // This will allow user to re-send email again
        context.getAuthenticationSession().removeAuthNote(Constants.VERIFY_EMAIL_KEY);

        requiredActionChallenge(context);
    }

    public String getDisplayType() {
        return PROVIDER_ID;
    }

    @Override
    public void close() {

    }

    @Override
    public RequiredActionProvider createDisplay(KeycloakSession session, String displayType) {
        if (displayType == null) return this;
        if (!OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(displayType)) return null;
        return CustomConsoleVerifyEmail.SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getDisplayText() {
        return PROVIDER_ID;
    }


    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /***
     * Has plain email
     * @param session
     * @param forms
     * @param user
     * @param authSession
     * @param event
     * @return
     * @throws UriBuilderException
     * @throws IllegalArgumentException
     */
    private Response sendVerifyEmail(KeycloakSession session, LoginFormsProvider forms, UserModel user,
                                     AuthenticationSessionModel authSession, EventBuilder event)
            throws UriBuilderException, IllegalArgumentException {

        RealmModel realm = session.getContext().getRealm();
        UriInfo uriInfo = session.getContext().getUri();

        int validityInSecs = realm.getActionTokenGeneratedByUserLifespan(VerifyEmailActionToken.TOKEN_TYPE);
        int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;

        String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
        VerifyEmailActionToken token = new VerifyEmailActionToken(user.getId(),
                absoluteExpirationInSecs,
                authSessionEncodedId,
                user.getEmail(),
                authSession.getClient().getClientId());
        UriBuilder builder = Urls.actionTokenBuilder(uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo),
                authSession.getClient().getClientId(), authSession.getTabId());
        String link = builder.build(realm.getName()).toString();
        long expirationInMinutes = TimeUnit.SECONDS.toMinutes(validityInSecs);

        try {
            EmailTemplateProvider provider = session.getProvider(EmailTemplateProvider.class,
                    "spi-freemarker");

            provider.setAuthenticationSession(authSession).setRealm(realm)
                    .setUser(user)
                    .sendVerifyEmail(link, expirationInMinutes);
            event.success();
        } catch (EmailException e) {
            logger.error("Custom Verify Email - Failed to send verification email", e);
            event.error(Errors.EMAIL_SEND_FAILED);
        }

        return forms.createResponse(UserModel.RequiredAction.VERIFY_EMAIL);
    }
}
