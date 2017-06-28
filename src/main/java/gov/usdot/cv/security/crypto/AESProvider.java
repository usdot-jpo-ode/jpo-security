package gov.usdot.cv.security.crypto;


import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.AesCcmCiphertext;

/**
 * AES in CCM mode encrypt/decrypt helper 
 */
public class AESProvider {
	
	/**
	 * Length of the nonce in bytes
	 */
	public static final int nonceLength = 12;
	private static final int keySize = 128;
	
	/**
	 * Length of the AES key in bytes
	 */
	public static final int keyLength = keySize/8;
	
	private final AESFastEngine aesEngine;
	private final  CCMBlockCipher aesccmEngine;
	
	/**
	 * Instantiates AES cipher
	 */
	public AESProvider() {
		aesEngine = new AESFastEngine();
		aesccmEngine = new CCMBlockCipher(aesEngine);
	}
	
	/**
	 * Encrypts clear text
	 * @param key symmetric key to use for encryption
	 * @param nonce to use
	 * @param clearText to encrypt
	 * @return encrypted text
	 * @throws CryptoException if encryption fails
	 */
	public byte[] encrypt(KeyParameter key, byte[] nonce, byte[] clearText) throws CryptoException {
		return encrypt(key, nonce, clearText, 0, clearText.length);
	}
	
	/**
	 * Encrypts clear text
	 * @param key symmetric key to use for encryption
	 * @param nonce to use
	 * @param clearText to encrypt
	 * @param start of the text
	 * @param length of the text
	 * @return encrypted text
	 * @throws CryptoException if encryption fails
	 */
	public byte[] encrypt(KeyParameter key, byte[] nonce, byte[] clearText, int start, int length) throws CryptoException {
		
		if ( clearText == null )
			return null;

		if ( nonce == null )
			throw new CryptoException("Invalid parameter nonce value must not be null.");
		if (nonce.length != nonceLength)
			throw new CryptoException(String.format("Invalid parameter nonce value. Expected: %d. Actual: %d", nonceLength, nonce.length));
		
		AEADParameters aesccmParameters = new AEADParameters(key, (int) keySize, nonce, null);
		byte[] cipherText;
		
		aesccmEngine.init(true, aesccmParameters);
		cipherText = new byte[clearText.length + keyLength];
		aesccmEngine.processBytes(clearText, 0, clearText.length, cipherText, 0);
		try {
			aesccmEngine.doFinal(cipherText, 0);
		} catch (Exception ex) {
			throw new CryptoException("Couldn't decrypt cipher text. Reason: " + ex.getMessage(), ex);
		}

		return cipherText;
			
	}
	
	/**
	 * Decrypts cipher text
	 * @param key symmetric key to use for decryption
	 * @param nonce to use
	 * @param cipherText to decrypt
	 * @return clear text
	 * @throws CryptoException if encryption fails
	 */
	public byte[] decrypt(KeyParameter key, byte[] nonce, byte[] cipherText) throws CryptoException {
		return decrypt(key, nonce, cipherText, 0, cipherText.length);
	}
	
	/**
	 * Decrypts cipher text
	 * @param key symmetric key to use for decryption
	 * @param nonce to use
	 * @param cipherText to decrypt
	 * @param start of cipher text
	 * @param length of cipher text
	 * @return clear text
	 * @throws CryptoException if encryption fails
	 */
	public byte[] decrypt(KeyParameter key, byte[] nonce, byte[] cipherText, int start, int length) throws CryptoException {
		
		if ( cipherText == null )
			return null;

		if ( nonce == null )
			throw new CryptoException("Invalid parameter nonce value must not be null.");
		if (nonce.length != nonceLength)
			throw new CryptoException(String.format("Invalid parameter nonce value. Expected: %d. Actual: %d", nonceLength, nonce.length));
		
		AEADParameters aesccmParameters = new AEADParameters(key, (int) keySize, nonce, null);
		
		byte[] plainText;
		
		aesccmEngine.init(false, aesccmParameters);
		plainText = new byte[length - keyLength];
		aesccmEngine.processBytes(cipherText, start, length, plainText, 0);
		try {
			int bytesProcessed = aesccmEngine.doFinal(plainText, 0);
			if (bytesProcessed != plainText.length) 
				throw new CryptoException(String.format("Couldn't decrypt cipher text. Reason: Bytes processed mismatch: processed %d vs. plain text %d.", bytesProcessed, plainText.length ));
		} catch (InvalidCipherTextException ex) {
			throw new CryptoException("Couldn't decrypt cipher text. Reason: " + ex.getMessage(), ex);
		} catch (Exception ex) {
			throw new CryptoException("Couldn't decrypt cipher text. Reason: " + ex.getMessage(), ex);
		}
			
		return plainText;
	}
	
	/**
	 * Decrypts cipher text
	 * @param key symmetric key to use for decryption
	 * @param cipherText to decrypt
	 * @return clear text
	 * @throws CryptoException if encryption fails
	 */
	public byte[] decrypt(KeyParameter key, AesCcmCiphertext cipherText) throws CryptoException {

		byte[] ccmCipherText = cipherText.getCcmCiphertext().byteArrayValue();
		byte[] nonce = cipherText.getNonce().byteArrayValue();
		
		return decrypt(key, nonce, ccmCipherText);
	}
	
	private static byte[] zeroKeyBytes;

	/**
	 * Generates non-zero symmetric encryption key
	 * @return newly generated key
	 */
	static public KeyParameter generateKey() {
		byte[] keyBytes;
		do {
			keyBytes = CryptoHelper.getSecureRandomBytes(keyLength);
		} while(Arrays.areEqual(keyBytes, zeroKeyBytes));
		return new KeyParameter(keyBytes);
	}
}
