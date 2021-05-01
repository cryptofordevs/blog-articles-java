package AttackCbcAndEcb.CbcBitFlipping;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * Solution of https://cryptopals.com/sets/2/challenges/16
 */
public class Main {

	public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException {
		Oracle oracle = new Oracle();
		oracle.init();
		byte[] cookie = oracle.createCookie("dadminbtrue");
		BitFlippingAttack bitFlippingAttack = new BitFlippingAttack(oracle);
		bitFlippingAttack.attack(cookie);
	}
}
