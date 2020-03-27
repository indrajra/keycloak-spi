package org.sunbird.keycloak.core;

import org.jboss.logging.Logger;
import org.keycloak.models.utils.Base32;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.spec.KeySpec;

public class EncryptionSevice {

	private static Logger logger = Logger.getLogger(EncryptionSevice.class);
	private static  String privateKeyStr;
	private static  String publicKeyStr;
	private static EncryptionSevice SINGLETON = null;
	private static Boolean lockFlag;

	public static EncryptionSevice instance() throws IOException {
		if (SINGLETON == null) {
			synchronized (EncryptionSevice.class) {
				if (SINGLETON == null) {
					SINGLETON = new EncryptionSevice();
				}
			}
		}
		return SINGLETON;
	}

	private EncryptionSevice() throws IOException {
		loadKeys();
	}

	void loadKeys() throws IOException {
			InputStream inputStream = EncryptionSevice.class.getResourceAsStream("/private.pem");
			InputStreamReader isReader = new InputStreamReader(inputStream);
			BufferedReader reader = new BufferedReader(isReader);
			StringBuffer sb = new StringBuffer();
			String str;
			while ((str = reader.readLine()) != null) {
				sb.append(str);
			}
			privateKeyStr = sb.toString();

			inputStream = EncryptionSevice.class.getResourceAsStream("/public.pem");
			isReader = new InputStreamReader(inputStream);
			reader = new BufferedReader(isReader);
			sb = new StringBuffer();
			while ((str = reader.readLine()) != null) {
				sb.append(str);
			}
			publicKeyStr = sb.toString();
	}

	// This works on data without case sensitivity
	public  String encrypt(String data) {
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(privateKeyStr.toCharArray(), publicKeyStr.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
			return Base32.encode(cipher.doFinal(data.toLowerCase().getBytes("UTF-8"))).toLowerCase();
		} catch (Exception e) {
			logger.error("Error while encrypting: " + e.toString());
		}
		return null;
	}
	
	public  String decrypt(String encryptedData) {
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(privateKeyStr.toCharArray(), publicKeyStr.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			return new String(cipher.doFinal(Base32.decode(encryptedData)));
		} catch (Exception e) {
			logger.error("Error while decrypting: " + e.toString());
		}
		return null;
	}
}
