package AttackCbcAndEcb.CbcBitFlipping;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

class BitFlippingAttack {

	private Oracle oracle;

	BitFlippingAttack(Oracle oracle) {
		this.oracle = oracle;
	}

	void attack(byte[] cipherText) throws InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException {
		int firstCharacterIdx = 16; // we know the structure so a small cheat here (byte we're interested in minus 16-block size)
		int secondCharacterIdx = 22; // we know the structure so a small cheat here (byte we're interested in minus 16-block size)
		for (int i = 0; i <= 255;i++) { //try all the values for first byte
			cipherText[firstCharacterIdx] = (byte) i;
			for (int j = 0; j <= 255;j++) {
				cipherText[secondCharacterIdx] = (byte) j; //try all the values for second byte
				boolean success = oracle.login(cipherText); //try to login
				if (success) {
					System.out.println("Success"); //display a message if success
					return;
				}
			}
		}
	}
}
