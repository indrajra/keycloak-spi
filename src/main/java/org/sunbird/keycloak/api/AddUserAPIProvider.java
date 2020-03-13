package org.sunbird.keycloak.api;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class AddUserAPIProvider implements RealmResourceProviderFactory {

  private static Logger logger =
      Logger.getLogger(AddUserAPIProvider.class);
  public static final String PROVIDER_ID = "users";

  @Override
  public String getId() {
    logger.debug("RestResourceProviderFactory: getId called ");
    return PROVIDER_ID;
  }

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new AddUserController(session);
  }

  @Override
  public void init(Scope config) {

  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {

  }

  @Override
  public void close() {

  }

}
