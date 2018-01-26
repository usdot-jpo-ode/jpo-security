package gov.usdot.cv.security.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.apache.log4j.Logger;

import com.oss.asn1.AbstractData;
import com.oss.asn1.Coder;
import com.oss.asn1.ControlTableNotFoundException;
import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;
import com.oss.asn1.InitializationException;

import gov.usdot.asn1.generated.ieee1609dot2.Ieee1609dot2;

/**
 * Helper for encoding/decoding OSS ASN.1 generated classes
 */
public class Ieee1609dot2Helper {
	private static final Logger logger = Logger.getLogger(Ieee1609dot2Helper.class);
	
   private static final Coder COERCoder = Ieee1609dot2.getCOERCoder();
   private static final Coder DERCoder = Ieee1609dot2.getDERCoder();
	
	static {
		try {
			COERCoder.enableAutomaticDecoding();
			COERCoder.enableAutomaticEncoding();
			COERCoder.enableContainedValueDecoding();
			COERCoder.enableContainedValueEncoding();
			
			DERCoder.enableAutomaticDecoding();
			DERCoder.enableAutomaticEncoding();
			DERCoder.enableContainedValueDecoding();
			DERCoder.enableContainedValueEncoding();
			
			Ieee1609dot2.initialize();
		} catch (ControlTableNotFoundException e) {
			logger.error("Failed to initiliaze Ieee1609dot2 environment ", e);
		} catch (InitializationException e) {
			logger.error("Failed to initiliaze Ieee1609dot2 environment ", e);
		}
	}
	
	/**
	 * Encode OSS ASN.1 generated class to COER bytes
	 * @param <T> AbstractData type parameter
	 * @param data OSS ASN.1 generated class to encode
	 * @return COER encoded byte array
	 * @throws EncodeNotSupportedException if encoding is not supported
	 * @throws EncodeFailedException if encoding failed
	 */
	public static <T extends AbstractData> byte[] encodeCOER(T data) throws EncodeFailedException, EncodeNotSupportedException {
		ByteArrayOutputStream sink = new ByteArrayOutputStream();
		COERCoder.encode(data, sink);
		
		return sink.toByteArray();
	}

	/**
	 * Decode COER bytes to OSS ASN.1 generated class
	 * @param bytes  COER encoded bytes
	 * @param <T> AbstractData type parameter
	 * @param dataType The OSS ASN.1 generate class the bytes should decode to
	 * @return instantiation of the OSS ASN.1 generated class
	 * @throws DecodeFailedException if decoding failed
	 * @throws DecodeNotSupportedException if decoding is not supported
	 */
	public static <T extends AbstractData> T decodeCOER(byte[] bytes, T dataType) 
												throws DecodeFailedException, DecodeNotSupportedException {
		ByteArrayInputStream bytesStream = new ByteArrayInputStream(bytes);
		@SuppressWarnings("unchecked")
      T data = (T)COERCoder.decode(bytesStream, dataType);
		
		return data;
	}

   /**
    * Encode OSS ASN.1 generated class to COER bytes
    * @param <T> AbstractData type parameter
    * @param data OSS ASN.1 generated class to encode
    * @return COER encoded byte array
    * @throws EncodeNotSupportedException if encoding is not supported
    * @throws EncodeFailedException if encoding failed
    */
   public static <T extends AbstractData> byte[] encodeDER(T data) throws EncodeFailedException, EncodeNotSupportedException {
      ByteArrayOutputStream sink = new ByteArrayOutputStream();
      DERCoder.encode(data, sink);
      
      return sink.toByteArray();
   }

   /**
    * Decode COER bytes to OSS ASN.1 generated class
    * @param bytes  COER encoded bytes
    * @param <T> AbstractData type parameter
    * @param dataType The OSS ASN.1 generate class the bytes should decode to
    * @return instantiation of the OSS ASN.1 generated class
    * @throws DecodeFailedException if decoding failed
    * @throws DecodeNotSupportedException if decoding is not supported
    */
   public static <T extends AbstractData> T decodeDER(byte[] bytes, T dataType) 
                                    throws DecodeFailedException, DecodeNotSupportedException {
      ByteArrayInputStream bytesStream = new ByteArrayInputStream(bytes);
      @SuppressWarnings("unchecked")
      T data = (T)DERCoder.decode(bytesStream, dataType);
      
      return data;
   }
}
