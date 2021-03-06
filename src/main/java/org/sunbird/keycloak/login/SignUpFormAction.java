package org.sunbird.keycloak.login;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.authentication.requiredactions.util.UpdateProfileContext;
import org.keycloak.authentication.requiredactions.util.UserUpdateProfileContext;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;
import org.sunbird.keycloak.core.CustomVerifyEmail;
import org.sunbird.keycloak.core.EncryptionSevice;
import org.sunbird.keycloak.core.OrgSupervisorMapping;

import javax.ws.rs.core.MultivaluedMap;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class SignUpFormAction implements FormAction, FormActionFactory {
    private static Logger logger = Logger.getLogger(SignUpFormAction.class);
    public static final String PROVIDER_ID = "spi-signup-form-action";
    private OrgSupervisorMapping orgSupervisorMapping;
    private EncryptionSevice encryptionService;

    public SignUpFormAction() {
        try {
            orgSupervisorMapping = new OrgSupervisorMapping();
            encryptionService = EncryptionSevice.instance();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (orgSupervisorMapping.getOrgSupervisorMap().isNull() || encryptionService == null) {
                throw new RuntimeException("Can't load keys and maps");
            }
        }
    }

    @Override
    public String getHelpText() {
        return "This action must always be first! Validates the username of the user in validation phase.  In success phase, this will create the user in the database.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    private boolean isEmailAllowed(String email) {
          return email.endsWith("@ekstep.org") ||
                email.endsWith("@societalplatform.org");
    }

    private String getDomain(String email) {
        String domain = "EkStep";
        if (email.endsWith("@societalplatform.org")) {
            domain = "Societal Platform";
        }
        return domain;
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList();
        context.getEvent().detail("register_method", "form");
        String email = (String)formData.getFirst("email");
        String username = (String)formData.getFirst("username");
        context.getEvent().detail("username", username);
        context.getEvent().detail("email", email);
        String usernameField = "username";

        String orgName = formData.getFirst("user.attributes.org");
        if (orgName == null || orgName.isEmpty()) {
            context.error("organization is not selected");
            errors.add(new FormMessage("org", "Select an organization where you work for"));
            context.validationError(formData, errors);
            return;
        }

        if (!isEmailAllowed(email) && !orgName.equals("testing")) {
            context.error("email_disallowed_from_registration");
            formData.remove("email");
            errors.add(new FormMessage("email", "Email is invalid"));
            context.validationError(formData, errors);
            return;
        }

        if (context.getRealm().isRegistrationEmailAsUsername()) {
            context.getEvent().detail("username", email);
            if (Validation.isBlank(email)) {
                errors.add(new FormMessage("email", "missingEmailMessage"));
            } else if (!Validation.isEmailValid(email)) {
                errors.add(new FormMessage("email", "invalidEmailMessage"));
                formData.remove("email");
            }

            if (errors.size() > 0) {
                context.error("invalid_registration - More than one error");
                context.validationError(formData, errors);
                return;
            }

            if (email != null && !context.getRealm().isDuplicateEmailsAllowed() &&
            		context.getSession().users().getUserByEmail(encryptionService.encrypt(email), context.getRealm()) != null) {
                context.error("email_in_use");
                formData.remove("email");
                errors.add(new FormMessage("email", "emailExistsMessage"));
                context.validationError(formData, errors);
                return;
            }
        } else {
            if (Validation.isBlank(username)) {
                context.error("invalid_registration - username is blank");
                errors.add(new FormMessage("username", "missingUsernameMessage"));
                context.validationError(formData, errors);
                return;
            }

            if (context.getSession().users().getUserByUsername(username, context.getRealm()) != null) {
                context.error("username_in_use");
                errors.add(new FormMessage(usernameField, "usernameExistsMessage"));
                formData.remove("username");
                context.validationError(formData, errors);
                return;
            }
        }

        context.success();
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {

    }

    private void sendToUtilService(FormContext context, String payload) {
        HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost("http://localhost:9081/register/users/self");
        StringEntity params = null;
        try {
            logger.info("Payload is " + payload);
            params = new StringEntity(payload);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return;
        }
        post.addHeader("content-type", "application/json");
        post.setEntity(params);
        boolean success = false;
        try {
            HttpResponse response = httpClient.execute(post);
            InputStream content = response.getEntity().getContent();
            try {
                Map json = JsonSerialization.readValue(content, Map.class);
                logger.info("Response from utils service" + json.toString());
            } finally {
                content.close();
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
    }

    private void addUserToRegistry(FormContext context, UserModel user, String userPlainEmail, String managerEmail) {
        String userDomain = getDomain(userPlainEmail);

        ObjectNode empData = JsonNodeFactory.instance.objectNode();
        empData.put("orgName", userDomain);
        empData.put("isActive", false);
        empData.put("isOnboarded", false);
        empData.put("name", user.getFirstName() + user.getLastName());
        empData.put("email", userPlainEmail);
        empData.put("manager", managerEmail);
        empData.put("kcid", user.getId());

        Date date = new Date();
        String modifiedDate= new SimpleDateFormat("yyyy-MM-dd").format(date);
        empData.put("startDate", modifiedDate);

        ObjectNode empNode = JsonNodeFactory.instance.objectNode();
        empNode.set("Employee", empData);

        ObjectNode selfRegistrationPayload = JsonNodeFactory.instance.objectNode();
        selfRegistrationPayload.put("id", "open-saber.registry.create");
        selfRegistrationPayload.set("request", empNode);

        sendToUtilService(context, selfRegistrationPayload.toString());
    }

    @Override
    public void success(FormContext context) {
        logger.info("SignupFormAction - Success method called");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String email = formData.getFirst(Validation.FIELD_EMAIL);
        String username = formData.getFirst(RegistrationPage.FIELD_USERNAME);
        String orgName = formData.getFirst("user.attributes.org");
        logger.info(username + " trying with org = " + orgName);

        if (isEmailAllowed(email) || orgName.equals("testing")) {
            String encryptedEmail = encryptionService.encrypt(email);
            logger.info("After encryption email is " + encryptedEmail);
            String firstName = formData.getFirst(RegistrationPage.FIELD_FIRST_NAME);
            String lastName = formData.getFirst(RegistrationPage.FIELD_LAST_NAME);

            String managerEmail = orgSupervisorMapping.getOrgSupervisorMap().get(orgName).asText();

            UserModel user = context.getSession().users().addUser(context.getRealm(), username);
            UpdateProfileContext userCtx = new UserUpdateProfileContext(context.getRealm(), user);
            userCtx.setFirstName(firstName);
            userCtx.setLastName(lastName);
            userCtx.setEmail(encryptedEmail);
            userCtx.setSingleAttribute("selfRegistered", String.valueOf(true));

            user.setEnabled(true);

            // Without setting this, next auth flows will break
            context.setUser(user);
            context.getEvent().user(user);
            context.getEvent().success();

            addUserToRegistry(context, user, email, managerEmail);
            user.addRequiredAction(CustomVerifyEmail.PROVIDER_ID);

        } else {
            context.getEvent().error("Disallowed registration. Can't recognize you, sorry!");
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        user.addRequiredAction(CustomVerifyEmail.PROVIDER_ID);
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "SPI New user registration";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }


    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
