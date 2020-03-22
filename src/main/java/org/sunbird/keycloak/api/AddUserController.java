package org.sunbird.keycloak.api;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.openshift.internal.restclient.model.kubeclient.User;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resource.RealmResourceProvider;
import org.sunbird.keycloak.Constants;
import org.sunbird.keycloak.core.EncryptionSevice;

public class AddUserController implements RealmResourceProvider {

	private static Logger logger = Logger.getLogger(AddUserController.class);
	private KeycloakSession session;
	protected UserProvider delegate;

	public AddUserController(KeycloakSession session) {
		this.session = session;
	}

	public UserProvider getDelegate() {
		if (delegate != null) return delegate;
		delegate = session.userStorageManager();

		return delegate;
	}


	public void createCredentials(UserRepresentation userRep, UserModel user, boolean adminRequest) {
		RealmModel realm = session.getContext().getRealm();
		logger.info("Sent creds count = " + userRep.getCredentials().size());
		if (userRep.getCredentials() != null) {
			for (CredentialRepresentation cred : userRep.getCredentials()) {
				if (cred.getType().equals("password")) {
					session.userCredentialManager().updateCredential(realm, user, UserCredentialModel.password(cred.getValue(), adminRequest));
					logger.info("Setting default credentials");
				}
			}
		}
	}

	public void setRequiredActions(UserRepresentation userRep, UserModel user) {
		if (userRep.getRequiredActions() != null) {
			for (String action : userRep.getRequiredActions()) {
				user.addRequiredAction(action);
			}
		}
	}

	/**
	 * The custom add user functionality. Encrypt the user PII here.
	 *
	 * @param userD
	 * @return
	 */
	@POST
	@Path("/add")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response addUser(UserRepresentation userD) {
		logger.info("Start - add user");
		checkRealmAdminAccess();
		try {
			userD.setId(KeycloakModelUtils.generateId());
			UserProvider userProvider = session.userStorageManager();
			// Change email to lowercase.
			String email = userD.getEmail().toLowerCase();
			EncryptionSevice encryptionSevice = new EncryptionSevice();
			String encryptedEmail = encryptionSevice.encrypt(email);
			userD.setEmail(encryptedEmail);

			if (checkUserExist(userD, userProvider)) {
				return ErrorResponse.error(Constants.USER_EXIST, Status.INTERNAL_SERVER_ERROR);
			}

			// Both addDefaultRoles and addDefaultRequiredActions are set to true
			UserModel user = getDelegate().addUser(session.getContext().getRealm(),
					userD.getId(), userD.getFirstName(), true, true);
			user.setEmail(encryptedEmail);
			user.setEmailVerified(userD.isEmailVerified());
			user.setFirstName(userD.getFirstName());
			user.setLastName(userD.getLastName());
			user.setUsername(userD.getUsername());
			user.setEnabled(true);
			createCredentials(userD, user,false);
			setRequiredActions(userD, user);

			return Response.ok(userD).build();
		} catch (Exception e) {
			logger.error(e);
			return ErrorResponse.error(e.getMessage(), Status.INTERNAL_SERVER_ERROR);
		}
	}

	private boolean checkUserExist(UserRepresentation userD, UserProvider userProvider) {
		UserModel user = userProvider.getUserByUsername(userD.getUsername(), session.getContext().getRealm());
		if (user == null) {
			// email is already encrypted in the userD
			user = userProvider.getUserByEmail(userD.getEmail(), session.getContext().getRealm());
			if (user == null) {
				return false;
			}
		}
		return true;
	}

	private void checkRealmAdminAccess() {
		logger.debug("RestResourceProvider: checkRealmAdminAccess called");

		AuthResult authResult = new AppAuthManager().authenticateBearerToken(session, session.getContext().getRealm());

		if (authResult == null) {
			logger.info("Authentication session is null");
			throw new WebApplicationException(ErrorResponse.error(Constants.ERROR_NOT_AUTHORIZED, Status.UNAUTHORIZED));
		} else if (authResult.getToken().getRealmAccess() == null
				|| !authResult.getToken().getRealmAccess().isUserInRole(Constants.ADMIN)) {
			logger.info("Forbidden - token related realm roles null or not admin");
			authResult.getToken().getRealmAccess().getRoles().iterator().forEachRemaining(s -> logger.debug((s)));

			throw new WebApplicationException(
					ErrorResponse.error(Constants.ERROR_REALM_ADMIN_ROLE_ACCESS, Status.FORBIDDEN));
		}
	}

	@Override
	public Object getResource() {
		return this;
	}

	@Override
	public void close() {

	}
}
