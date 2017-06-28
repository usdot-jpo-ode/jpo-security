package gov.usdot.cv.security.crypto;

/**
 * Cryptographic exception
 */
public class CryptoException extends Exception {

	private static final long serialVersionUID = 1L;

	public CryptoException() {
	}

	public CryptoException(String message) {
		super(message);
	}

	public CryptoException(Throwable cause) {
		super(cause);
	}

	public CryptoException(String message, Throwable cause) {
		super(message, cause);
	}

}
