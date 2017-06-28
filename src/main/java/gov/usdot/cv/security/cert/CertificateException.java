package gov.usdot.cv.security.cert;

/**
 * 1609.2 Certificate exception
 */
public class CertificateException extends Exception {

	private static final long serialVersionUID = -3938018903389940966L;

	public CertificateException(String message) {
		super(message);
	}

	public CertificateException(Throwable cause) {
		super(cause);
	}

	public CertificateException(String message, Throwable cause) {
		super(message, cause);
	}

}
