package AttackCbcAndEcb.RestoreIfKeyAsIV;

import java.util.Arrays;

import static util.Util.concatArrays;

/**
 * Implementation based on Sayooj Samuel's idea
 * from https://crypto.stackexchange.com/questions/16161/problems-with-using-aes-key-as-iv-in-cbc-mode
 *
 * Extremely dangerous if two conditions are met:
 * Decryption is allowed for user
 * Key and IV are the same
 */
class InitializationVectorRestorer {

	/**
	 * Assuming 16 bit block size
	 */
	private final static int BLOCK_SIZE = 16;

	byte[] createMessageToDecrypt(byte[] ciphertext) {
		ciphertext = extendCipherText(ciphertext); // to handle padding two last blocks must remain the same so I'm copying one block

		//setting zeros in the second block
		for (int i = BLOCK_SIZE; i < 2 * BLOCK_SIZE;i++) {
			ciphertext[i] = 0x00;
		}

		// copying first block into 3rd one
		int distanceBetweenBlocks = 2 * BLOCK_SIZE;
		for (int i = distanceBetweenBlocks; i < distanceBetweenBlocks + BLOCK_SIZE;i++) {
			ciphertext[i] = ciphertext[i-distanceBetweenBlocks];
		}
		return ciphertext;
	}

	String restoreInitializationVector(byte[] decrypted) {
		int startIdx = 2 * BLOCK_SIZE;
		byte[] recoveredKey = new byte[BLOCK_SIZE];
		// see the blog article to understand why does it work
		for (int i = 0; i < BLOCK_SIZE;i++) {
			recoveredKey[i] = (byte) ((decrypted[i] ^ decrypted[startIdx + i]));
		}
		return new String(recoveredKey);
	}

	// method to build up extended ciphertext
	private byte[] extendCipherText(byte[] cipherText) {
		byte[] firstThreeBlock = Arrays.copyOfRange(cipherText, 0, 48);
		byte[] thirdBlock = Arrays.copyOfRange(cipherText, 32, 48);
		byte[] padding = Arrays.copyOfRange(cipherText, 48, 64);
		byte[] tmp = concatArrays(firstThreeBlock, thirdBlock);
		return concatArrays(tmp, padding);
	}
}
