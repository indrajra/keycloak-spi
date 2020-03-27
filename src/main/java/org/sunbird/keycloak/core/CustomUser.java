package org.sunbird.keycloak.core;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.adapter.InMemoryUserAdapter;

import java.io.IOException;

public class CustomUser {
    private static final Logger logger = Logger.getLogger(CustomUser.class);
    private EncryptionSevice encryptionService = null;

    public CustomUser() {
        initEncService();
    }

    public CustomUser(KeycloakSession session, RealmModel realm, UserModel userModel) {
        //super(session, realm, userModel.getId());
        initEncService();
    }

    public void initEncService() {
        try {
            encryptionService = EncryptionSevice.instance();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public UserModel findUserByNameOrEmail(KeycloakSession session , RealmModel realm, String username) {
        logger.info("CustomFindUsersByNameOrEmail");
        if (realm.isLoginWithEmailAllowed() && username.indexOf(64) != -1) {
            UserModel user = session.users().getUserByEmail(encryptionService.encrypt(username), realm);
            if (user != null) {
                return user;
            }
        }

        logger.info("Finding by user name");
        // Usernames are plain text
        return session.users().getUserByUsername(username, realm);
    }
}
