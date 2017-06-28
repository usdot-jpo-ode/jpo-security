package gov.usdot.cv.security.util;

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Time64;

public class Time64HelperTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(Time64HelperTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}

	@Test
	public void testNow() {
		Date now = new Date();
		log.debug("Current date/time: " + now);
		Time64 time64 = Time64Helper.dateToTime64(now);
		Date decodedDate = Time64Helper.time64ToDate(time64);
		log.debug("Decoded date/time: " + decodedDate);
		assertEquals(now, decodedDate);
	}

	@Test
	public void testFixedValues() {
		long[] fixedValues = {
				0,
				1234567,
				12345678,
				123456789,
				1234567890,
				0x7fffffff,
				123456789012345L,
				1234567890123456L,
				12345678901234567L,
				123456789012345679L,
				0x00010c01ee7771bfL,
				0x00010c01ee75eb4bL,
				0x00020c01ee75eb4bL,
				0x00030c01ee75eb4bL,
				0x000F0c01ee75eb4bL,
		};
		for( long fixedValue : fixedValues )
			testFixedValue(fixedValue);
	}
	
	public void testFixedValue(long fixedValue) {
		log.debug(String.format("Testing fixed value 0x%xl. (%d)", fixedValue, fixedValue));
		ByteBuffer bb = ByteBuffer.allocate(8);
		bb.putLong(fixedValue);
		bb.rewind();
		Time64 decodedFixedValue = new Time64(bb.getLong());
		Date decodedDate = Time64Helper.time64ToDate(decodedFixedValue);
		Time64 convertedFixedValue = Time64Helper.dateToTime64(decodedDate);
		log.debug("Decoded fixed date: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(decodedDate));
		assertEquals(fixedValue, decodedFixedValue.longValue());
		assertEquals(decodedFixedValue.longValue()/1000,
					convertedFixedValue.longValue()/1000);
	}

}
