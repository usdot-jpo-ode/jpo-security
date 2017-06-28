package gov.usdot.cv.security.util;

import java.util.Calendar;
import java.util.Date;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Duration;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Time32;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.ValidityPeriod;

/**
 * 6.4.15 Time32 Helper
 * Time32 is an unsigned 32-bit integer giving the number of seconds since 00:00:00 UTC, 1 January, 2004. 
 */
public class Time32Helper {
	
	
	static final long time32ValueAdjustment;
	
	static {
		Calendar calendar = Calendar.getInstance();
		calendar.set(2004, Calendar.JANUARY, 1, 0, 0, 0);
		time32ValueAdjustment = calendar.getTime().getTime();
	}

	/**
	 * Converts Time32 to java.util.Date
	 * @param time32 as ASN.1 Generated Time32
	 * @return time as java.util.Date
	 */
	public static Date time32ToDate(Time32 time32) {
		return new Date(time32.longValue()*1000 + time32ValueAdjustment);
	}
	
	/**
	 * Converts java.util.Date to Time32 with rounding
	 * @param date java.util.Date to convert
	 * @return number of seconds since 00:00:00 UTC, 1 January, 2004 as ASN.1 generated Time32.
	 */	
	public static Time32 dateToTime32(Date date) {
		return new Time32((date.getTime() - time32ValueAdjustment + 500)/1000);
	}
	
	public static Date calculateEndDate(ValidityPeriod validityPeriod) {
		return calculateEndDate(validityPeriod.getStart(), validityPeriod.getDuration());
	}
	
	public static Date calculateEndDate(Time32 startDate, Duration duration) {
		Calendar validToDate = Calendar.getInstance();
		validToDate.setTime(time32ToDate(startDate));
		
		if(duration.hasMicroseconds()) {
			// Convert to milliseconds: 1 millisecond = 1000 microseconds
			validToDate.add(Calendar.MILLISECOND, duration.getMicroseconds().intValue() / 1000);
		}
		else if(duration.hasMilliseconds()) {
			validToDate.add(Calendar.MILLISECOND, duration.getMilliseconds().intValue());
		}
		else if(duration.hasSeconds()) {
			validToDate.add(Calendar.SECOND, duration.getSeconds().intValue());
		}
		else if(duration.hasMinutes()) {
			validToDate.add(Calendar.MINUTE, duration.getMinutes().intValue());
		}
		else if(duration.hasHours()) {
			validToDate.add(Calendar.HOUR, duration.getHours().intValue());
		}
		else if(duration.hasSixtyHours()) {
			// Convert to hours
			validToDate.add(Calendar.HOUR, duration.getSixtyHours().intValue() * 60);
		}
		else if(duration.hasYears()) {
			validToDate.add(Calendar.YEAR, duration.getYears().intValue());
		}
		
		return validToDate.getTime();
	}
}