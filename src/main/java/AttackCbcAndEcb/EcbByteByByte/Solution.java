package AttackCbcAndEcb.EcbByteByByte;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.Random;

/**
 * Solution to https://cryptopals.com/sets/2/challenges/14
 * When we have AES_ECB(uknownValue || our value || secret, KEY) we can decrypt the unknown secret without knowing the key
 */
public class Solution {

	private static final String unknownText = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"+
					"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
					"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

	public static void main(String[] args) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {

		Random rand = new Random();
		int i = rand.nextInt(13) + 5;
		byte[] randomBytes = new byte[i];

		byte[] unknownTextInBytes = Base64.getDecoder().decode(unknownText);
		Oracle oracle = new Oracle();
		oracle.init();
		EcbDecryptor ecbDecryptor = new EcbDecryptor(oracle);
		String s = ecbDecryptor.decryptUnknownText(randomBytes, unknownTextInBytes);
		System.out.println("Result: " + s);
	}
}
