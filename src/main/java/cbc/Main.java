package cbc;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Base64;

public class Main {

	public static void main(String[] args) throws GeneralSecurityException {
		// generate a key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey secretKey = keyGen.generateKey();

		// generate a IV
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		IvParameterSpec ivParams = new IvParameterSpec(iv);

		//plaintext
		byte[] plainText = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
				,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

		//init cipher and encrypt
		Cipher cbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cbc.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
		byte[] cipherText = cbc.doFinal(plainText);

		System.out.println(Base64.getEncoder().encode(cipherText));
		System.out.println("");
	}

}
