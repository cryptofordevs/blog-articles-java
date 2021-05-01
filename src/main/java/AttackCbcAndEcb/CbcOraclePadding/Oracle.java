package AttackCbcAndEcb.CbcOraclePadding;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

class Oracle {
	private SecretKey key;
	private Cipher cipher;

	Oracle() {
	}

	void init() {
		try {
			this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			this.key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}

	EncryptionResult encrypt(byte[] plainText) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
		IvParameterSpec parameterSpec = generateIV();
		cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
		byte[] cipherText = cipher.doFinal(plainText);
		return new EncryptionResult(cipherText, parameterSpec);
	}

	byte[] decrypt(final IvParameterSpec IV, final byte[] cipherText) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
		cipher.init(Cipher.DECRYPT_MODE, key, IV);
		return cipher.doFinal(cipherText);
	}

	private IvParameterSpec generateIV() {
		byte[] IV = new byte[16];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(IV);
		return new IvParameterSpec(IV);
	}

	class EncryptionResult  {
		private byte[] cipherText;
		private IvParameterSpec parameterSpec;

		EncryptionResult(byte[] cipherText, IvParameterSpec parameterSpec) {
			this.cipherText = cipherText;
			this.parameterSpec = parameterSpec;
		}

		public byte[] getCipherText() {
			return cipherText;
		}

		public IvParameterSpec getParameterSpec() {
			return parameterSpec;
		}
	}
}
