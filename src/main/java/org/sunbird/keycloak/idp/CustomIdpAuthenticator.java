package org.sunbird.keycloak.idp;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.UserModel;
import org.sunbird.keycloak.core.EncryptionSevice;

public class CustomIdpAuthenticator extends IdpCreateUserIfUniqueAuthenticator {
    String prefix = "idpAuth_";

    @Override
   // Empty method by default. This exists, so subclass can override and add callback after new user is registered through social
   protected void userRegisteredSuccess(AuthenticationFlowContext context, UserModel registeredUser, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

    	EncryptionSevice encryptionService = new EncryptionSevice();
        registeredUser.setEmail(prefix +encryptionService.encrypt(registeredUser.getEmail()));
   }


    // Could be overriden to detect duplication based on other criterias (firstName, lastName, ...)
    protected ExistingUserInfo checkExistingUser(AuthenticationFlowContext context, String username, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

    	EncryptionSevice encryptionService = new EncryptionSevice();
        if (brokerContext.getEmail() != null && !context.getRealm().isDuplicateEmailsAllowed()) {
            UserModel existingUser = context.getSession().users().getUserByEmail(encryptionService.encrypt(brokerContext.getEmail().substring(prefix.length())), context.getRealm());
            if (existingUser != null) {
                return new ExistingUserInfo(existingUser.getId(), UserModel.EMAIL, encryptionService.decrypt(existingUser.getEmail()));
            }
        }

        UserModel existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());
        if (existingUser != null) {
            return new ExistingUserInfo(existingUser.getId(), UserModel.USERNAME, existingUser.getUsername());
        }

        return null;
    }
}
