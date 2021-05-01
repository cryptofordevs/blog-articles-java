package AttackCbcAndEcb.CbcBitFlipping;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

class Oracle {
	private SecretKey key;
	private Cipher cipher;
	private IvParameterSpec IV;

	Oracle() {
	}

	void init() {
		try {
			this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			IV = generateIV();
			keyGen.init(128);
			this.key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}

	byte[] createCookie(String userData) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
		userData = userData.replaceAll("=", "").replaceAll(";", "");
		String plainText = "comment1=cooking%20MCs;userdata=" + userData + ";comment2=%20like%20a%20pound%20of%20bacon";

		cipher.init(Cipher.ENCRYPT_MODE, key, IV);
		byte[] cipherText = cipher.doFinal(plainText.getBytes());
		return cipherText;
	}

	boolean login(final byte[] cipherText) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
		cipher.init(Cipher.DECRYPT_MODE, key, IV);
		byte[] bytes = cipher.doFinal(cipherText);
		String loginData = new String(bytes);
		return loginData.contains(";admin=true;");
	}

	private IvParameterSpec generateIV() {
		byte[] IV = new byte[16];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(IV);
		return new IvParameterSpec(IV);
	}
}
