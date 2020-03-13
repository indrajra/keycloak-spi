package org.sunbird.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SignUpFormAction implements FormAction,FormActionFactory {
	public static final String PROVIDER_ID = "signup-form";
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
        List<FormMessage> errors = new ArrayList<>();
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        String email = formData.getFirst(Validation.FIELD_EMAIL);
        String phone = formData.getFirst("user.attributes.phone");
        String age = formData.getFirst("user.attributes.age");
        String username = formData.getFirst(RegistrationPage.FIELD_USERNAME);
        context.getEvent().detail(Details.USERNAME, username);
        context.getEvent().detail(Details.EMAIL, email);

        String usernameField = RegistrationPage.FIELD_USERNAME;
        if (context.getRealm().isRegistrationEmailAsUsername()) {
            context.getEvent().detail(Details.USERNAME, email);

            if (Validation.isBlank(email)) {
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.MISSING_EMAIL));
            } else if (!Validation.isEmailValid(email)) {
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.INVALID_EMAIL));
                formData.remove(Validation.FIELD_EMAIL);
            }
           
            if (errors.size() > 0) {
                context.error(Errors.INVALID_REGISTRATION);
                context.validationError(formData, errors);
                return;
            }
            if (email != null && !context.getRealm().isDuplicateEmailsAllowed() && context.getSession().users().getUserByEmail(email, context.getRealm()) != null) {
                context.error(Errors.EMAIL_IN_USE);
                formData.remove(Validation.FIELD_EMAIL);
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.EMAIL_EXISTS));
                context.validationError(formData, errors);
                return;
            } 
        } else {
            if (Validation.isBlank(username)) {
                context.error(Errors.INVALID_REGISTRATION);
                errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.MISSING_USERNAME));
                context.validationError(formData, errors);
                return;
            }

            if (context.getSession().users().getUserByUsername(username, context.getRealm()) != null) {
                context.error(Errors.USERNAME_IN_USE);
                errors.add(new FormMessage(usernameField, Messages.USERNAME_EXISTS));
                formData.remove(Validation.FIELD_USERNAME);
                context.validationError(formData, errors);
                return;
            }

        }
        String eventError = Errors.INVALID_REGISTRATION;
        if (Validation.isBlank(phone)) {
        	context.error("Missing Phone Number.");
            errors.add(new FormMessage("Phone", "Missing Phone."));
            context.validationError(formData, errors);
            return;
        } 
        if (Validation.isBlank(age)) {
        	context.error("Missing Age.");
        	errors.add(new FormMessage("Age", "Missing Age."));
        	context.validationError(formData, errors);
        	return;
        }
        if (errors.size() > 0) {
			context.error(eventError);
			context.validationError(formData, errors);
			return;

		} else {
			formData = context.getHttpRequest().getDecodedFormParameters();
	        context.getHttpRequest().getDecodedFormParameters().put(Validation.FIELD_EMAIL, new ArrayList(Arrays.asList("encrypted_email_"+email)));
			context.success();
		}
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {

    }

    @Override
    public void success(FormContext context) {
    	System.out.println("success method called");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String email = formData.getFirst(Validation.FIELD_EMAIL);
        String username = formData.getFirst(RegistrationPage.FIELD_USERNAME);
        String phone = formData.getFirst("user.attributes.phone");
        String age = formData.getFirst("user.attributes.age");
        UserModel user = context.getSession().users().addUser(context.getRealm(), "encUserName_"+username);
        user.setAttribute("phone", new ArrayList<>(Arrays.asList("encryptedPhone_"+phone)));
        user.setAttribute("age", new ArrayList<>(Arrays.asList(age)));
        user.setFirstName(formData.getFirst(RegistrationPage.FIELD_FIRST_NAME));
        user.setLastName(formData.getFirst(RegistrationPage.FIELD_LAST_NAME));
        user.setEmail(email);
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
        return "New user registration";
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
