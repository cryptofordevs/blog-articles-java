package AttackCbcAndEcb.CbcOraclePadding;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

//Inspired by https://cryptopals.com/sets/3/challenges/17
public class Main {

	public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, UnsupportedEncodingException {
		Oracle oracle = new Oracle();
		oracle.init();
		String plainText = "TheLongestPlainTextICouldThinkOf";
		Oracle.EncryptionResult encryptionResult = oracle.encrypt(plainText.getBytes());

		OraclePaddingAttack oraclePaddingAttack = new OraclePaddingAttack(oracle, encryptionResult);
		byte[] attack = oraclePaddingAttack.attack();
		String x1 = new String(attack);
		System.out.println(x1);
	}
}
