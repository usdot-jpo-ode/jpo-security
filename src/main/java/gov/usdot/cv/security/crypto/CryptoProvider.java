package gov.usdot.cv.security.crypto;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.ThreadedSeedGenerator;


/**
 * A collection of cryptographic providers to be used in a single thread
 *
 */
public class CryptoProvider {

	private static final SecureRandom secureRandom = new SecureRandom();
	
	private SHA256Digest digest = null;
	private AESProvider symmetricCipher = null;
	private ECDSAProvider signer = null;
	private ECIESProvider ecies = null;

	/**
	 * Retrieves cryptographic provider for calculating SHA-256 digest per FIPS 180-2.
	 * @return digest cryptographic provider
	 */
	public synchronized SHA256Digest getDigestProvider() {
		if ( digest == null )
			digest = new SHA256Digest();
		return digest;
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
		if ( bytes == null )
			return null;
		SHA256Digest digestProvider = getDigestProvider();
		digestProvider.reset();
		digestProvider.update(bytes, start, length);
		byte[] digest = new byte[digestProvider.getDigestSize()];
		digestProvider.doFinal(digest, 0);
		return digest;
	}

	/**
	 * Retrieves AES cryptographic provider
	 * @return AES cryptographic provider
	 */
	public synchronized AESProvider getSymmetricCipher() {
		if ( symmetricCipher == null )
			symmetricCipher = new AESProvider();
		return symmetricCipher;
	}
	
	/**
	 * Retrieves ECDSA cryptographic provider
	 * @return ECDSA cryptographic provider
	 */
	public synchronized ECDSAProvider getSigner() {
		if ( signer == null )
			signer = new ECDSAProvider(this);
		return signer;
	}
	
	/**
	 * Retrieves ECIES cryptographic provider
	 * @return ECIES cryptographic provider
	 */
	public synchronized ECIESProvider getECIESProvider() {
		if ( ecies == null )
			ecies = new ECIESProvider(this);
		return ecies;
	}
	
	/**
	 * Initializes cryptographic environment. Should be called once on process startup.  
	 */
	public static void initialize() {
		secureRandom.nextInt(); 							// forces seeding and thus saves about 50 ms later on
		new ThreadedSeedGenerator().generateSeed(23, true); // triggers BC init that saves about 200 ms later on
	}
	
	/**
	 * Retrieves shared instance of secure random
	 * @return secure random instance
	 */
	public static SecureRandom getSecureRandom() {
		return secureRandom;
	}

}
