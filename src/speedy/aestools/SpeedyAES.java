package speedy.aestools;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SpeedyAES {
	Cipher cip;
	static final int TAGLENGTH = 16;
	private final int KEYSIZE = 256, IVLENGTH = 12;
	private SecretKey key;
	private byte[] IV;

	public static void main(String[] args) throws IOException, IllegalBlockSizeException, BadPaddingException {
		SpeedyAES sAES = new SpeedyAES("Top Secret Password Bro");

		File testFile = new File("./data/test.mp4");

		FileInputStream fis = new FileInputStream(testFile);
		FileOutputStream fos = new FileOutputStream(new File("./data/enc.mp4"), true);
		while(true) {
		byte[] buff = fis.readNBytes(1000000000);
		if(buff.length < 1000000000) {
			//final
				fos.write(sAES.encrypt(buff));
				System.out.println("encrypt: final ln "+sAES.encrypt(buff).length);
			//
			break;
		} else {
			//every other time
				fos.write(sAES.encrypt(buff));
				System.out.println("encrypt: ln "+sAES.encrypt(buff).length);
			//
		}
		}
		fos.flush();
		fos.close();
		fis.close();
		
		
		
		FileInputStream fis2 = new FileInputStream(new File("./data/enc.mp4"));
		FileOutputStream fos2 = new FileOutputStream(new File("data/out.mp4"), true);
		
		while(true) {
			///NOTE TO SELF - THIS WORKS BECAUSE WHEN READING THE ALREADY ENCRYPTED FILE YOU MUST FACTOR IN THE TAG LENGTH OF 16 BYTES FOR EACH SECTION
			byte[] buff = fis2.readNBytes(1000000016);
			if(buff.length < 1000000016) {
				//final
					fos2.write(sAES.decrypt(buff));
					System.out.println("decrypt: final ln "+sAES.decrypt(buff).length);
				//
				break;
			} else {
				//every other time
					fos2.write(sAES.decrypt(buff));
					System.out.println("decrypt: ln "+sAES.decrypt(buff).length);
				//
			}
			}
			fos2.flush();
			fos2.close();
			fis2.close();
		
		
	}

	// initialize from SecretKey
	public SpeedyAES(SecretKey key) {
		this.key = key;
		init();

	}

	// initialize from plain-text password
	public SpeedyAES(String password) {
		try {
			SecretKeyFactory sKF = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

			SecureRandom rand = new SecureRandom();
			byte[] salt = new byte[8];
			rand.nextBytes(salt);

			KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);

			SecretKey keyTmp = sKF.generateSecret(spec);
			this.key = new SecretKeySpec(keyTmp.getEncoded(), "AES");

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.err.println("FATAL INTERNAL ERROR - CONTACT DEVELOPER");
			e.printStackTrace();
		}

		init();
	}

	// initialization vector generation
	private void init() {
		IV = new byte[IVLENGTH];
		SecureRandom rand = new SecureRandom();
		rand.nextBytes(IV);
	}

	public byte[] encrypt(byte[] input) {
		try {
			return encrypt(input, IV, key);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.err.println("Error in encryption method. (SpeedyAES)");
			e.printStackTrace();
		}
		return null;
	}

	public byte[] decrypt(byte[] input) {
		try {
			return decrypt(input, IV, key);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
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

	public Cipher getEncryptCipher() {
		try {
			Cipher cip = Cipher.getInstance("AES/GCM/NoPadding");
			SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

			GCMParameterSpec gcmPSpec = new GCMParameterSpec(TAGLENGTH * 8, IV);

			cip.init(Cipher.ENCRYPT_MODE, keySpec, gcmPSpec);
			return cip;
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;

	}

	public Cipher getDecryptCipher() {
		try {
			Cipher cip = Cipher.getInstance("AES/GCM/NoPadding");
			SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

			GCMParameterSpec gcmPSpec = new GCMParameterSpec(TAGLENGTH * 8, IV);

			cip.init(Cipher.DECRYPT_MODE, keySpec, gcmPSpec);
			return cip;
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

}
