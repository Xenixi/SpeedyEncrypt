package speedy.aestools;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

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
	static private int bufferSize = 1000000000;

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
			e.printStackTrace();
		}

		return null;
	}

	// for large amounts of data ( and small amounts too :) )
	public boolean blockEncrypt(InputStream is, OutputStream os) {
		try {
			while (true) {

				byte[] buffer = is.readNBytes(bufferSize);

				os.write(encrypt(buffer));
				if (buffer.length < bufferSize) {
					return true;
				}

			}

		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}

	}

	public boolean blockDecrypt(InputStream is, OutputStream os) {
		try {
			while (true) {

				byte[] buffer = is.readNBytes(bufferSize + TAGLENGTH);

				os.write(decrypt(buffer));
				if (buffer.length < (bufferSize + TAGLENGTH)) {
					return true;
				}

			}

		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	// TEST METHOD
	/*
	 * public static void main(String[] args) throws IOException {
	 * System.out.println("Encrypting..."); File testFile = new
	 * File("./data/test.mp4"); FileInputStream fis = new FileInputStream(testFile);
	 * SpeedyAES sAES = new SpeedyAES("krjgw543V$TW#$t$f"); FileOutputStream fos =
	 * new FileOutputStream(new File("./data/enc.mp4"), true);
	 * 
	 * sAES.blockEncrypt(fis, fos);
	 * 
	 * fis.close(); fos.flush(); fos.close();
	 * 
	 * System.out.println("Decrypting..."); FileInputStream fis2 = new
	 * FileInputStream(new File("./data/enc.mp4")); FileOutputStream fos2 = new
	 * FileOutputStream(new File("./data/output.mp4"), true);
	 * 
	 * sAES.blockDecrypt(fis2, fos2);
	 * 
	 * fis2.close(); fos2.flush(); fos2.close();
	 * System.out.println("Task completed.");
	 * 
	 * }
	 */

}
