package speedy.rsatools;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public final class SpeedyRSA {
	private int bits;

	public SpeedyRSA(int bits) {
		this.bits = bits;
	}

	public int getBitNumber() {
		return bits;
	}

	public KeyPair generateKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(bits);
			return kpg.generateKeyPair();

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;

	}

	public byte[] encrypt(byte[] data, PublicKey publicKey) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");

			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(data);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public byte[] decrypt(byte[] data, PrivateKey privateKey) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return cipher.doFinal(data);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
