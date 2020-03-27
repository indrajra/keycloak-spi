package org.sunbird.keycloak.idp;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.UserModel;
import org.sunbird.keycloak.core.EncryptionSevice;

import java.io.IOException;

public class CustomIdpAuthenticator extends IdpCreateUserIfUniqueAuthenticator {
   private EncryptionSevice encryptionService = null;

   public CustomIdpAuthenticator() {
       try {
           encryptionService = EncryptionSevice.instance();
       } catch (IOException e) {
           e.printStackTrace();
       }
   }

   private String getEncryptedEmail(String email) {
       return encryptionService.encrypt(email.toLowerCase());
   }

   private String getEmail(UserModel user) {
       return getEncryptedEmail(user.getEmail());
   }

    @Override
   // Empty method by default. This exists, so subclass can override and add callback after new user is registered through social
   protected void userRegisteredSuccess(AuthenticationFlowContext context, UserModel registeredUser, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        registeredUser.setEmail(getEmail(registeredUser));
   }


    // Could be overriden to detect duplication based on other criterias (firstName, lastName, ...)
    protected ExistingUserInfo checkExistingUser(AuthenticationFlowContext context, String username, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

        if (brokerContext.getEmail() != null && !context.getRealm().isDuplicateEmailsAllowed()) {
            UserModel existingUser = context.getSession().users().getUserByEmail(getEncryptedEmail(brokerContext.getEmail()), context.getRealm());
            if (existingUser != null) {
                return new ExistingUserInfo(existingUser.getId(), UserModel.EMAIL, existingUser.getEmail());
            }
        }

        UserModel existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());
        if (existingUser != null) {
            return new ExistingUserInfo(existingUser.getId(), UserModel.USERNAME, existingUser.getUsername());
        }

        return null;
    }
}
