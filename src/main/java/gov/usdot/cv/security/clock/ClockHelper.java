
package gov.usdot.cv.security.clock;

import java.util.Date;

/**
 * Helper class that is used by the library to get current time.
 * All methods should use this and never use System.currentTimeMillis() or new Date() directly.
 * This is to allow unit test to move time back and use fixed (and thus potentially expired) certificates.
 */
public final class ClockHelper {

	private static long offset = 0;

	/**
	 * Get current time as Date
	 * @return current time as Date
	 */
	public static Date nowDate() {
		return new Date(now());
	}

	/**
	 * Get current time in milliseconds
	 * @return current time in milliseconds
	 */
	public static long now() {
		return System.currentTimeMillis() - offset;
	}

	/**
	 * Sets perceived system current time to the provided milliseconds since the epoch
	 * @param millis milliseconds since the epoch
	 */
	static synchronized void setNow(long millis) {
		ClockHelper.offset = System.currentTimeMillis() - millis;
	}

	/**
	 * Sets perceived system current time to the date provided
	 * @param date to become new perceived system current time
	 */
	static void setNow(Date date) {
		setNow(date.getTime());
	}
	
	/**
	 * Resets perceived system current time to actual system time
	 */
	static void reset() {
		ClockHelper.offset = 0;
	}

}
