package gov.usdot.cv.security.crypto;


import java.security.interfaces.ECPrivateKey;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.AesCcmCiphertext;

/**
 * A collection of cryptographic helper functions to be used in a single thread
 */
public class CryptoHelper {

	private final CryptoProvider cryptoProvider;
	
	/**
	 * Instantiates cryptographic helper with new CryptoHelper
	 */
	public CryptoHelper() {
		this(new CryptoProvider());
	}
	
	/**
	 * Instantiates cryptographic helper with supplied cryptographic provider
	 * @param cryptoProvider for use by this helper
	 */
	public CryptoHelper(CryptoProvider cryptoProvider) {
		this.cryptoProvider = cryptoProvider;
	}
	
	/**
	 * Calculates SHA-256 digest of the bytes provided
	 * @param bytes to calculate the digest of
	 * @return calculated SHA-256 digest
	 */
	public byte[] computeDigest(byte[] bytes) {
		return computeDigest(bytes, 0, bytes.length);
	}
	
	/**
	 * Calculates SHA-256 digest of the bytes provided
	 * @param bytes to calculate the digest of
	 * @param start of the bytes for digest
	 * @param length of the bytes for digest
	 * @return calculated SHA-256 digest
	 */
	public byte[] computeDigest(byte[] bytes, int start, int length ) {
		return cryptoProvider.computeDigest(bytes, start, length);
	}
	
	/**
	 * Generates random sequence of bytes
	 * @param length of the sequence to generate
	 * @return generated random sequence of bytes
	 */
	public static byte[] getSecureRandomBytes(int length) {
		byte[] randomBytes = new byte[length];
		CryptoProvider.getSecureRandom().nextBytes(randomBytes);
		return randomBytes;
	}
	
	/**
	 * Encrypts clear text
	 * @param key symmetric key to use for encryption
	 * @param nonce to use
	 * @param clearText to encrypt
	 * @return encrypted text
	 * @throws CryptoException if encryption fails
	 */
	public byte[] encryptSymmetric(KeyParameter key, byte[] nonce, byte[] clearText) throws CryptoException {
		return cryptoProvider.getSymmetricCipher().encrypt(key, nonce, clearText);
	}
	
	/**
	 * Decrypts cipher text
	 * @param key symmetric key to use for decryption
	 * @param nonce to use
	 * @param cipherText to decrypt
	 * @return clear text
	 * @throws CryptoException if encryption fails
	 */
	public byte[] decryptSymmetric(KeyParameter key, byte[] nonce, byte[] cipherText) throws CryptoException {
		return cryptoProvider.getSymmetricCipher().decrypt(key, nonce, cipherText);
	}
	
	/**
	 * Decrypts cipher text
	 * @param key symmetric key to use for decryption
	 * @param cipherText to decrypt
	 * @return clear text
	 * @throws CryptoException if encryption fails
	 */
	public byte[] decryptSymmetric(KeyParameter key, AesCcmCiphertext cipherText) throws CryptoException {
		return cryptoProvider.getSymmetricCipher().decrypt(key, cipherText);
	}
	
	/**
	 * Computes message signature
	 * @param toBeSignedDataBytes bytes of the ToBeSignedData
	 * @param signingCertificateBytes bytes of the certificate performing the signing
	 * @param signingPrivateKey alias of private signing key to use
	 * @return wrapped message signature
	 */
	public EcdsaP256SignatureWrapper computeSignature(byte[] toBeSignedDataBytes, byte[] signingCertificateBytes,
															ECPrivateKey signingPrivateKey) {
		return cryptoProvider.getSigner().computeSignature(toBeSignedDataBytes, signingCertificateBytes, signingPrivateKey);
	}
	
   /**
    * Computes message signature
    * @param toBeSignedDataBytes bytes of the ToBeSignedData
    * @param signingCertificateBytes bytes of the certificate performing the signing
    * @param signingPrivateKey private signing key to use
    * @return wrapped message signature
    */
   public EcdsaP256SignatureWrapper computeSignature(byte[] toBeSignedDataBytes, byte[] signingCertificateBytes,
                                             ECPrivateKeyParameters signingPrivateKey) {
      return cryptoProvider.getSigner().computeSignature(toBeSignedDataBytes, signingCertificateBytes, signingPrivateKey);
   }
   
	/**
	 * Validates message signature
	 * @param toBeSignedDataBytes bytes of the ToBeSignedData
	 * @param signingCertificateBytes bytes of the certificate which performed the signing
	 * @param signingPublicKey public signing key to use
	 * @param signature ECDSA signature wrapper
	 * @return true if the signature is valid and false otherwise
	 */
	public boolean verifySignature(byte[] toBeSignedDataBytes, byte[] signingCertificateBytes,
									ECPublicKeyParameters signingPublicKey, EcdsaP256SignatureWrapper signature) {
		return toBeSignedDataBytes != null ? 
					cryptoProvider.getSigner().verifySignature(toBeSignedDataBytes, signingCertificateBytes, signingPublicKey, signature) :
					false;
	}
}
