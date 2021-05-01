package AttackCbcAndEcb.EcbByteByByte;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class Oracle {

	private SecretKey key;
	private Cipher cipher;

	Oracle() {
	}

	void init() {
		try {
			this.cipher = Cipher.getInstance("AES/ECB/NoPadding");
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			this.key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}

	byte[] encrypt(byte[] plainText) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(plainText);
	}

	byte[] decrypt(final byte[] cipherText) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(cipherText);
	}
}
