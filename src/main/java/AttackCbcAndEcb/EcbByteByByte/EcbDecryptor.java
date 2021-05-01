package AttackCbcAndEcb.EcbByteByByte;

import util.Util;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * only for ebc with no padding
 */
class EcbDecryptor {

	private final Oracle oracle;

	EcbDecryptor(Oracle oracle) {
		this.oracle = oracle;
	}

	String decryptUnknownText(byte[] randomText, byte[] unknownText) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
		int blockLength = identifyBlockLength();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < unknownText.length;i++) {
			//looking for matching byte for each byte from a ciphertext
			byte aByte = findByte(randomText, unknownText[i], blockLength);
			sb.append(new String(new byte[]{aByte}));
		}
		return sb.toString();
	}

	private int identifyBlockLength() {
		StringBuilder sb = new StringBuilder();
		while (true) {
			sb.append("A");
			try {
				oracle.encrypt(sb.toString().getBytes());
				return sb.length();
			} catch (Exception ex) {
				// Don't do it in production. Code only for demonstrating purposes
			}
		}
	}

	private byte findByte(byte[] randomText, byte character, int blockLength) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < blockLength - 1; i++) {
			sb.append("A");
		}
		sb.append(new String(new byte[]{character}));
		byte[] bytes = addRandomText(randomText, blockLength);
		byte[] encrypt1 = oracle.encrypt(buildPlainText(bytes, sb.toString().getBytes()));
		String x = Util.bytesToHex(encrypt1);

		//matching
		Map<byte[] , String> dictionaries = buildDictionary(randomText, blockLength);
		for (Map.Entry<byte[], String> row: dictionaries.entrySet()) {
			if (x.equals(row.getValue())) {
				return row.getKey()[row.getKey().length-1];
			}
		}
		return 0;
	}

	// making a dictionary for each possible byte value e.g AAAAAAAA,AAAAAAAB etc
	private Map<byte[], String> buildDictionary(byte[] randomText, int blockLength) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < blockLength - 1; i++) {
			sb.append("A");
		}
		Map<byte[], String> dictionaries = new HashMap<>();
		for (int i = 0; i < 256;i++) {
			sb.append(new String(new byte[]{(byte)i}));
			if (sb.toString().length() == blockLength) {
				try {
					byte[] bytes = addRandomText(randomText, blockLength);
					byte[] plainText = buildPlainText(bytes, sb.toString().getBytes());
					byte[] encrypt = oracle.encrypt(plainText);
					dictionaries.put(plainText, Util.bytesToHex(encrypt));
				} catch (Exception e) {
					// Don't do it in production. Code only for demonstrating purposes
				}
				sb.deleteCharAt(sb.length()-1);
			}
		}
		return dictionaries;
	}

	private byte[] buildPlainText(byte[] a, byte[] b) {
		byte[] result = new byte[a.length+b.length];
		int i = 0;
		for (; i < a.length;i++) {
			result[i] = a[i%a.length];
		}
		int j;
		for (j = 0; j < b.length;j++) {
			result[j + i] = b[j%b.length];
		}
		return result;
	}

	private byte[] addRandomText(byte[] randomText, int blockLength) {
		int toFill = randomText.length % blockLength;
		byte[] array = Arrays.copyOfRange(randomText, 0, randomText.length + blockLength - toFill);
		for (int i = randomText.length; i < array.length; i++) {
			array[i] = (byte)'A';
		}
		return array;
	}
}
