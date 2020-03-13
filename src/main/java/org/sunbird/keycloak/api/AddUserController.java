package org.sunbird.keycloak.api;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resource.RealmResourceProvider;
import org.sunbird.keycloak.Constants;

public class AddUserController implements RealmResourceProvider {

	private static Logger logger = Logger.getLogger(AddUserController.class);
	private KeycloakSession session;

	public AddUserController(KeycloakSession session) {
		this.session = session;
	}

	/**
	 * The custom add user functionality. Encrypt the user PII here.
	 * @param userD
	 * @return
	 */
	@POST
	@Path("/add")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response addUser(UserRepresentation userD) {
		logger.debug("Start - add user");
		checkRealmAdminAccess();

		try {
			userD.setId(KeycloakModelUtils.generateId());
//
//      System.out.println("REALM: "+session.getContext().getRealm());
//      UserModel user = session.userLocalStorage().addUser(session.getContext().getRealm(),userD.getUsername()+"_test");
//      user.setEnabled(userD.isEnabled() != null && userD.isEnabled());
//      //user.setCreatedTimestamp(userRep.getCreatedTimestamp());
//      user.setEmail(userD.getEmail());
//      user.setEmailVerified(userD.isEmailVerified() != null && userD.isEmailVerified());
//      user.setFirstName(userD.getFirstName());
//      user.setLastName(userD.getLastName());
//      if (userD.getRequiredActions() != null) {
//          for (String requiredAction : userD.getRequiredActions()) {
//              user.addRequiredAction(UserModel.RequiredAction.valueOf(requiredAction.toUpperCase()));
//          }
//      }
//      
			UserModel user = RepresentationToModel.createUser(session, session.getContext().getRealm(), userD);
			return Response.ok(user).build();
		} catch (Exception e) {
			return ErrorResponse.error(Constants.ERROR_CREATE_LINK, Status.INTERNAL_SERVER_ERROR);
		}
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
