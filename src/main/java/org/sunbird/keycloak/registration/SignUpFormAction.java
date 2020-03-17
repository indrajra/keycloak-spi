package org.sunbird.keycloak.registration;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.authentication.requiredactions.util.UpdateProfileContext;
import org.keycloak.authentication.requiredactions.util.UserUpdateProfileContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;

public class SignUpFormAction implements FormAction, FormActionFactory {
    private static Logger logger = Logger.getLogger(SignUpFormAction.class);
    public static final String PROVIDER_ID = "spi-signup-form-action";

    public SignUpFormAction() {}

    @Override
    public String getHelpText() {
        return "This action must always be first! Validates the username of the user in validation phase.  In success phase, this will create the user in the database.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
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
        if (context.getRealm().isRegistrationEmailAsUsername()) {
            context.getEvent().detail("username", email);
            if (Validation.isBlank(email)) {
                errors.add(new FormMessage("email", "missingEmailMessage"));
            } else if (!Validation.isEmailValid(email)) {
                errors.add(new FormMessage("email", "invalidEmailMessage"));
                formData.remove("email");
            }

            if (errors.size() > 0) {
                context.error("invalid_registration");
                context.validationError(formData, errors);
                return;
            }

            if (email != null && !context.getRealm().isDuplicateEmailsAllowed() && context.getSession().users().getUserByEmail(email, context.getRealm()) != null) {
                context.error("email_in_use");
                formData.remove("email");
                errors.add(new FormMessage("email", "emailExistsMessage"));
                context.validationError(formData, errors);
                return;
            }
        } else {
            if (Validation.isBlank(username)) {
                context.error("invalid_registration");
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

    @Override
    public void success(FormContext context) {
        logger.info("SignupFormAction - Success method called");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String email = formData.getFirst(Validation.FIELD_EMAIL);
        String username = formData.getFirst(RegistrationPage.FIELD_USERNAME);
//        String phone = formData.getFirst("user.attributes.phone");
//        String age = formData.getFirst("user.attributes.age");
        // FIXME: Encrypt email and store
        UserModel user = context.getSession().users().addUser(context.getRealm(), "encUserName_"+username);
//        user.setAttribute("phone", new ArrayList<>(Arrays.asList("encryptedPhone_"+phone)));
//        user.setAttribute("age", new ArrayList<>(Arrays.asList(age)));

        UpdateProfileContext userCtx = new UserUpdateProfileContext(context.getRealm(), user);
        userCtx.setFirstName(formData.getFirst(RegistrationPage.FIELD_FIRST_NAME) + "ChangedF");
        userCtx.setLastName(formData.getFirst(RegistrationPage.FIELD_LAST_NAME) + "ChangedL");
        userCtx.setEmail(email);
        user.setEnabled(true);

        context.setUser(user);
        context.getEvent().user(user);
        context.getEvent().success();
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

    //@Override
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
