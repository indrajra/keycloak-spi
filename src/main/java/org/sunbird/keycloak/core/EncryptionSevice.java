package org.sunbird.keycloak.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.logging.Logger;

import com.google.common.io.BaseEncoding;

public class EncryptionSevice {

	private static Logger logger = Logger.getLogger(EncryptionSevice.class);
	private static  String privateKeyStr;
	private static  String publicKeyStr;

	public EncryptionSevice() throws IOException {
		try {
			loadKeys();
		} catch (IOException e) {
			logger.error("Error while initialization of encryption service"+e);
			throw e;
		}
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
			return BaseEncoding.base32().lowerCase().encode(cipher.doFinal(data.getBytes("UTF-8")));
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
			return new String(cipher.doFinal(BaseEncoding.base32().lowerCase().decode(encryptedData)));
		} catch (Exception e) {
			logger.error("Error while decrypting: " + e.toString());
		}
		return null;
	}
}
