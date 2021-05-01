package AttackCbcAndEcb.RestoreIfKeyAsIV;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * This package illustrate how to exploit relatively often misuse relying on using the same values for key and IV
 * in a CBC mode
 */
public class Solution {

	public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		// Never, never use keys like this one. I did it only to show that we can restore it if use as an IV
		String key = "testtesttesttest";
		SecretKeySpec sks = new SecretKeySpec(key.getBytes(), "AES");

		// Never, never use IV like this one. I did it only to show that we can restore it if use as an IV
		IvParameterSpec ivParams = new IvParameterSpec(key.getBytes());
		cipher.init(Cipher.ENCRYPT_MODE, sks, ivParams);

		//just an example plain text
		String plainText = "SecretMessage123SecretMessage123SecretMessage123";

		byte[] cipherText = cipher.doFinal(plainText.getBytes());

		InitializationVectorRestorer initializationVectorRestorer = new InitializationVectorRestorer();
		// we need to modify the ciphertext accordingly
		byte[] messageToDecrypt = initializationVectorRestorer.createMessageToDecrypt(cipherText);

		//our decryption oracle
		cipher.init(Cipher.DECRYPT_MODE, sks, ivParams);

		byte[] decrypted = cipher.doFinal(messageToDecrypt);

		System.out.println(initializationVectorRestorer.restoreInitializationVector(decrypted));
	}
}
