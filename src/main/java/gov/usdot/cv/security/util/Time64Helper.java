package gov.usdot.cv.security.util;

import java.util.Calendar;
import java.util.Date;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Time64;

/**
 * 6.3.11 Time64 helper
 * Time64 is an unsigned 64-bit integer giving the number of microseconds since 00:00:00 UTC, 1 January, 2004.
 */
public class Time64Helper {
	
	static final long time64ValueAdjustment;
	
	static {
		Calendar calendar = Calendar.getInstance();
		calendar.set(2004, Calendar.JANUARY, 1, 0, 0, 0);
		time64ValueAdjustment = calendar.getTime().getTime();
	}
	
	/**
	 * Converts Time64 value to java.util.Date.
	 * Note that this conversion will result in loss of microseconds present in time64 value
	 * @param time64 value to convert to Date
	 * @return converted java.util.Date value
	 */
	public static Date time64ToDate(Time64 time64) {
		assert(time64.longValue() != 0);
		
		long microToMilliseconds = time64.longValue() / 1000;
		long timeAdjusted = microToMilliseconds + time64ValueAdjustment;
		
		return new Date(timeAdjusted);
	}
	
	/**
	 * Converts java.util.Date to Time64 time in microseconds
	 * @param date java.util.Date to convert
	 * @return number of microseconds since 00:00:00 UTC, 1 January, 2004.
	 */
	public static Time64 dateToTime64(Date date) {
		long asMillisecondsTimeAdjusted = date.getTime() - time64ValueAdjustment;
		long milliToMicroseconds = asMillisecondsTimeAdjusted * 1000;
		
		return new Time64(milliToMicroseconds);
	}

}
