package org.sunbird.keycloak.core;

import java.io.IOException;

class EncryptionSeviceTest {
        public static void main(String[] args) {
            try {
                EncryptionSevice encryptionSevice = EncryptionSevice.instance();
                String email = "regtest3@yopmail.com";
                String email2 = "RegTest3@yopmail.com";
                String encryptedEmail = encryptionSevice.encrypt(email);
                String encryptedEmail2 = encryptionSevice.encrypt(email2);

                System.out.println(encryptedEmail + "\n" + encryptedEmail2);

                String decryptedEmail = encryptionSevice.decrypt(encryptedEmail);
                String decryptedEmail2 = encryptionSevice.decrypt(encryptedEmail2);
                System.out.println(decryptedEmail + "\n" + decryptedEmail2);

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
}