package gov.usdot.cv.security.clock;

import gov.usdot.cv.security.util.UnitTestHelper;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class ClockHelperTest {

	final static private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(ClockHelperTest.class);
	
	private static final String dateInThePast = "Tue Oct 14 15:19:26 EDT 2014";

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}
	
	public static void setNow(String dateStr) throws ParseException {
		setNow(getDate(dateStr));
	}
	
	public static void setNow(Date date) {
		log.debug("Setting perceived system current time to " + date);
		ClockHelper.setNow(date);
	}

	@Test
	public void test() throws ParseException, InterruptedException {
		log.debug("Actual  date:   " + ClockHelper.nowDate());
		Date desiredDate = getDate(dateInThePast);
		log.debug("Desired date:   " + desiredDate);
		ClockHelper.setNow(desiredDate);
		log.debug("Perceived date: " + ClockHelper.nowDate());
		Thread.sleep(1000);
		log.debug("Perceived date: " + ClockHelper.nowDate());
		ClockHelper.reset();
		log.debug("Actual  date:   " + ClockHelper.nowDate());
	}
	
	private static Date getDate(String dateStr) throws ParseException {
		return new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", Locale.ENGLISH).parse(dateStr);
	}

}
