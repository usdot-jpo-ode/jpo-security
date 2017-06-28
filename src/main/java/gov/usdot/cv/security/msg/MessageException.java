package gov.usdot.cv.security.msg;

/**
 * 1609.2 Message exception
 */
public class MessageException extends Exception {

	private static final long serialVersionUID = 1L;

	public MessageException(String message) {
		super(message);
	}

	public MessageException(Throwable cause) {
		super(cause);
	}

	public MessageException(String message, Throwable cause) {
		super(message, cause);
	}

}
