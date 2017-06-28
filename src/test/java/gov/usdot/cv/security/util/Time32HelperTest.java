package gov.usdot.cv.security.util;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Time32;

public class Time32HelperTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(Time32HelperTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}

	@Test
	public void testNow() {
		Date now = new Date();
		log.debug("Current date: " + now);
		Time32 time32in = Time32Helper.dateToTime32(now);
		log.debug("Current time32: " + time32in);
		Date decodedDate = Time32Helper.time32ToDate(time32in);
		log.debug("Decoded date: " + decodedDate);
		Time32 time32out = Time32Helper.dateToTime32(decodedDate);
		log.debug("Decoded time32: " + time32out);
		decodedDate = Time32Helper.time32ToDate(time32out);
		log.debug("Decoded date: " + decodedDate);
		assertEquals(time32in, time32out);
		//assertEquals(now.toString(), decodedDate.toString());
		//assertEquals((now.getTime()+500)/1000, (decodedDate.getTime()+500)/1000);
	}

	@Test
	public void testFixedValues() {
		int[] fixedValues = {
				-1,
				0,
				1234567,
				12345678,
				123456789,
				1234567890,
				0x7fffffff,
				0xcafebabe,
				0xdeadfeef,
				0xfffffeec,
		};
		for( int fixedValue : fixedValues )
			testFixedValue(fixedValue);
	}
	
	public void testFixedValue(int time32) {
		log.debug(String.format("Encode  seconds 0x%x.", time32));
		ByteBuffer bb = ByteBuffer.allocate(4);
		bb.putInt(time32);
		bb.rewind();
		Time32 time32out = new Time32(bb.getInt());
		log.debug(String.format("Decoded seconds 0x%x.", time32out.intValue()));
		Date decodedDate = Time32Helper.time32ToDate(time32out);
		log.debug("Decoded fixed date: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(decodedDate));
		assertEquals(time32, time32out.intValue());
	}
}
