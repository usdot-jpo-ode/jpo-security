package gov.usdot.cv.security.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;

/**
 * Implementation of 2609.2-2016 standard's description of the MAC used for ECIES encryption (5.3.5)
 */
public class Ieee1609dot2Mac1 extends HMac {

	private int tagBytes;
	
	/**
	 * Instantiates the MAC with a specified digest and authentication tag size
	 * @param digest  the digest the MAC uses
	 * @param tagBytes  the number of bytes the resulting authentication tag should be 
	 */
	public Ieee1609dot2Mac1(Digest digest, int tagBytes) {
		super(digest);
		this.tagBytes = tagBytes;
	}
	
	@Override
	public int getMacSize() {
		return tagBytes;
	}
	
	@Override
	public int doFinal(byte[] out, int outOff) {
		byte[] hmacOut = new byte[super.getMacSize()];
		
		int len = super.doFinal(hmacOut, outOff);
		System.arraycopy(hmacOut, 0, out, 0, tagBytes);
		
		return len;
	}
	
}
