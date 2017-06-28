package gov.usdot.cv.security.crypto;

import java.math.BigInteger;

import org.apache.log4j.Logger;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import com.oss.asn1.OctetString;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EcdsaP256Signature;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Signature;
import gov.usdot.cv.security.util.ByteArrayHelper;

/**
 * Wrapper class for EcdsaP256Signature (6.3.29) to decode/store/encode values as BigIntegers to be
 * used with Bouncy Castle Cryptography classes
 */
public class EcdsaP256SignatureWrapper {
	
	private static final Logger log = Logger.getLogger(EcdsaP256SignatureWrapper.class);
	
	final BigInteger r, s;
	
	/**
	 * Construct signature from r and s BigIntegers
	 * @param r r-value
	 * @param s s-value
	 */
	public EcdsaP256SignatureWrapper(BigInteger r, BigInteger s) {
		this.r = r;
		this.s = s;
	}
	
	/**
	 * Encode EcdsaP256Signature as x_coordinate_only.
	 * @return encoded signature
	 * @throws CryptoException if encoding fails
	 */
	public Signature encode() throws CryptoException {
		
		EcdsaP256Signature ecdsaNistP256Signature = new EcdsaP256Signature();
		EccP256CurvePoint encodedR = 
							EccP256CurvePoint.createEccP256CurvePointWithX_only(
												new OctetString(encodeBigInteger(r, ECDSAProvider.ECDSAPublicKeyEncodedLength-1)));
		OctetString encodedS = new OctetString(encodeBigInteger(s, ECDSAProvider.ECDSAPublicKeyEncodedLength-1));
		
		ecdsaNistP256Signature.setR(encodedR);
		ecdsaNistP256Signature.setS(encodedS);
		
		Signature signature = Signature.createSignatureWithEcdsaNistP256Signature(ecdsaNistP256Signature);
		
		return signature;
	}
	
	/**
	 * Decode Signature (6.3.28)
	 * @param signature  Signature to decode from
	 * @param signer helper provider used to help decode public key
	 * @return EcdsaP256SignatureWrapper instance
	 */
	static public EcdsaP256SignatureWrapper decode(Signature signature, ECDSAProvider signer) {
		EcdsaP256Signature ecdsaP256Signature = (signature.hasEcdsaNistP256Signature()) ?
													(signature.getEcdsaNistP256Signature()) :
													(signature.getEcdsaBrainpoolP256r1Signature());
													
		EccP256CurvePoint r = ecdsaP256Signature.getR();
		
		BigInteger rBigInt = null;
		if (r.hasX_only()) {
			rBigInt = decodeBigInteger(r.getX_only().byteArrayValue());
		}
		else if(r.hasCompressed_y_0() ||
				r.hasCompressed_y_1() ||
				r.hasUncompressed()) {
			ECPublicKeyParameters publicKey = signer.decodePublicKey(r);
			rBigInt = publicKey.getQ().getAffineXCoord().toBigInteger();
		}
		else {
			log.error(String.format("Unexpected EccP256CurvePoint Type value %d", r.getChosenFlag()));
			return null;
		}
		
		BigInteger sBigInt = decodeBigInteger(ecdsaP256Signature.getS().byteArrayValue());
		
		return new EcdsaP256SignatureWrapper(rBigInt, sBigInt);
	}

	/**
	 * Helper method for encoding value as BigInteger with padding
	 * @param value value to encode
	 * @param byteCount number of bytes to output
	 * @return byte array for the value as BigInteger with padding
	 * @throws CryptoException on cryptographic errors
	 */
	static public byte[] encodeBigInteger(BigInteger value, int byteCount) throws CryptoException {
		byte[] returnBytes;
		
		byte[] byteValue = value.toByteArray();
		if (byteValue.length > byteCount + 1) {
			String err = String.format(
							"Couldn't encode BigInteger value due to value overflow. Value length %d. ByteCount %d",
							byteValue.length, byteCount);
			log.error(err);
			throw new CryptoException(err);
		} else if (byteValue.length == byteCount + 1) {
			final int zeroByteValue = byteValue[0] & 0xFF;
			if (zeroByteValue != (EccP256CurvePoint.x_only_chosen-1)) {
				String err = String.format(
								"Couldn't encode BigInteger value due to unexpected first byte. Expected byte value 0. Actual byte value %d",
								zeroByteValue);
				log.error(err);
				throw new CryptoException(err);
			}
			returnBytes = new byte[byteValue.length-1];
			System.arraycopy(byteValue, 1, returnBytes, 0, byteValue.length-1);
		} else if (byteValue.length < byteCount) {
			returnBytes = ByteArrayHelper.concat(new byte[byteCount - byteValue.length], byteValue);
		}
		else {
			returnBytes = byteValue;
		}
		
		return returnBytes;
	}
	
	/**
	 * Decodes a byte array to a BigInteger
	 * @param bytes  the bytes to decode into a BigInteger
	 * @return the decoded BigInteger
	 */
	static public BigInteger decodeBigInteger(byte[] bytes) {
		return new BigInteger((int) 1, bytes);
	}
}