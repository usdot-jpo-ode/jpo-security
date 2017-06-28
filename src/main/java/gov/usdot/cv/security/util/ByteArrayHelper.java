package gov.usdot.cv.security.util;

import org.apache.log4j.Logger;

/**
 * Helper for working with byte arrays
 */
public class ByteArrayHelper {

	private static final Logger log = Logger.getLogger(ByteArrayHelper.class);
	
	/**
	 * Prepend a byte array with a single byte
	 * @param value  the byte to prepend
	 * @param array  the array to prepend the value to
	 * @return a new array consisting of the value prepended to the array
	 */
	public static byte[] prepend(final byte value, final byte[] array) {
		byte[] prepended = new byte[array.length + 1];
		
		prepended[0] = value;
		System.arraycopy(array, 0, prepended, 1, array.length);
		
		return prepended;
	}
	
	/**
	 * Concatenate two arrays such that array a is before array b 
	 * @param a  the array to use as the first part of the final array
	 * @param b  the array to use as the second part of the final array
	 * @return a new array consisting of array a concatenated with array b
	 */
	public static byte[] concat(final byte[] a, final byte[] b) {
		byte[] concatenated = new byte[a.length + b.length];
		System.arraycopy(a, 0, concatenated, 0, a.length);
		System.arraycopy(b, 0, concatenated, a.length, b.length);
		
		return concatenated;
	}
}
