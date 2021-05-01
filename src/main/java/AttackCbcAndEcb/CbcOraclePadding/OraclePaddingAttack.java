package AttackCbcAndEcb.CbcOraclePadding;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;

import static util.Util.concatArrays;

class OraclePaddingAttack {

	private static final int BLOCK_SIZE = 16;
	private final Oracle oracle;
	private final Oracle.EncryptionResult encryptionResult;

	OraclePaddingAttack(Oracle oracle, Oracle.EncryptionResult encryptionResult) {
		this.oracle = oracle;
		this.encryptionResult = encryptionResult;
	}

	byte[] attack() {
		byte[] cipherText = encryptionResult.getCipherText();

		byte[] result = new byte[0];
		int blockNumber = encryptionResult.getCipherText().length / BLOCK_SIZE;
		for (int i = 0; i < blockNumber; i++) {
			byte[] previousBlock;
			if (i == 0) { // in case of first block, we need to use IV as a previous block
				previousBlock = encryptionResult.getParameterSpec().getIV();
			} else {
				previousBlock = Arrays.copyOfRange(cipherText, (i - 1) * BLOCK_SIZE, i * BLOCK_SIZE);
			}
			byte[] targetBlock = Arrays.copyOfRange(cipherText, i*BLOCK_SIZE, (i+1)*BLOCK_SIZE);
			byte[] bytes = decryptBlock(previousBlock, targetBlock, i==blockNumber-1);
			result = concatArrays(result, bytes);
		}

		return result;
	}

	private byte[] decryptBlock(byte[] previousBlock, byte[] targetBlock, boolean isLastBlock) {
		byte[] originalPreviousBlock = Arrays.copyOf(previousBlock, previousBlock.length);
		byte[] X = new byte[BLOCK_SIZE];
		int originalPaddingLength = calculatePaddingLength(previousBlock, targetBlock);
		int paddingLength = (originalPaddingLength == BLOCK_SIZE) ? 0 : originalPaddingLength;

		for (int i = targetBlock.length - paddingLength; i<targetBlock.length;i++) {
			X[i] = (byte) (previousBlock[i] ^ (byte)(paddingLength));
		}

		int idx;
		int i = targetBlock.length - paddingLength - 1;
		for (; i>=0; i--) {
			idx = targetBlock.length - paddingLength;
			for (int j = idx; j<targetBlock.length; j++) {
				previousBlock[j] = (byte) (X[j] ^ (byte)(paddingLength+1));
			}
			for (int k = 0; k < 256; k++) {
				previousBlock[idx-1] = (byte) k;
				boolean isPaddingCorrect = oracleWrapper(concatArrays(previousBlock, targetBlock));
				if (isPaddingCorrect) {
					X[idx-1] = (byte)(previousBlock[idx-1] ^ (byte)(paddingLength+1));
					paddingLength++;
				}
			}
		}

		int blockSize = isLastBlock ? BLOCK_SIZE - originalPaddingLength : BLOCK_SIZE;
		byte[] result = new byte[blockSize];
		for (int j = 0; j< blockSize;j++) {
			result[j] = (byte)(originalPreviousBlock[j]^X[j]);
		}
		return result;
	}

	private int calculatePaddingLength(byte[] previousBlock, byte[] targetBlock) {
		int index = previousBlock.length-1;
		int cnt = 0;
		byte[] tmp = Arrays.copyOf(previousBlock, previousBlock.length);
		for (int cntLoop = 0; cntLoop < previousBlock.length; cntLoop++) {
			for (int i = 0; i < 256; i++) {
				tmp[index - cnt] = (byte) i;
				boolean isPaddingCorrect = oracleWrapper(concatArrays(tmp, targetBlock));
				if (!isPaddingCorrect) {
					tmp[index-cnt] = previousBlock[index-cnt];
					cnt++;
					break;
				}
			}
		}
		return cnt;
	}

	private boolean oracleWrapper(byte[] tmpCipherText) {
		try {
			byte[] decrypt = oracle.decrypt(encryptionResult.getParameterSpec(), tmpCipherText);
		} catch (IllegalBlockSizeException e) {

		} catch (BadPaddingException e) {
			return false;
		} catch (InvalidAlgorithmParameterException e) {
			// Don't do it in production. Code only for demonstrating purposes
		} catch (InvalidKeyException e) {
			// Don't do it in production. Code only for demonstrating purposes
		}
		return true;
	}
}
