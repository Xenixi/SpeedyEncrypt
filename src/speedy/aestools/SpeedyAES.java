package speedy.aestools;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SpeedyAES {
	Cipher cip;
	static final int TAGLENGTH = 16;

	public static void main(String[] args) throws IOException {
		// Testing method
		//final int KEYSIZE = 256, IVLENGTH = 12;

		//KeyGenerator gen;
		/*
		 * try { gen = KeyGenerator.getInstance("AES");
		 * 
		 * gen.init(KEYSIZE);
		 * 
		 * SecretKey key = gen.generateKey(); byte[] IV = new byte[IVLENGTH];
		 * 
		 * SecureRandom random = new SecureRandom(); random.nextBytes(IV);
		 * 
		 * 
		 * SpeedyAES instance = new SpeedyAES(); //TESTING PURPOSES
		 * 
		 * File encryptedFolder = new File("./data/encrypt");
		 * 
		 * for(File encryptedFile : encryptedFolder.listFiles()) { FileInputStream fis =
		 * new FileInputStream(encryptedFile); FileOutputStream fos = new
		 * FileOutputStream(new File("./data/decrypt/") + encryptedFile.getName());
		 * fos.write(instance.decrypt(fis.readAllBytes(), IV, key)); fis.close();
		 * fos.close(); }
		 * 
		 * 
		 * } catch (NoSuchAlgorithmException | InvalidKeyException |
		 * InvalidAlgorithmParameterException | IllegalBlockSizeException |
		 * BadPaddingException | NoSuchPaddingException e) { // TODO Auto-generated
		 * catch block e.printStackTrace(); }
		 */
	}

	public byte[] encrypt(byte[] input, byte[] IV, SecretKey key)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		cip = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

		GCMParameterSpec gcmPSpec = new GCMParameterSpec(TAGLENGTH * 8, IV);

		cip.init(Cipher.ENCRYPT_MODE, keySpec, gcmPSpec);

		return cip.doFinal(input);

	}

	public byte[] decrypt(byte[] input, byte[] IV, SecretKey key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		cip = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
		GCMParameterSpec gcmPSpec = new GCMParameterSpec(TAGLENGTH * 8, IV);

		cip.init(Cipher.DECRYPT_MODE, keySpec, gcmPSpec);

		return cip.doFinal(input);

	}
}
