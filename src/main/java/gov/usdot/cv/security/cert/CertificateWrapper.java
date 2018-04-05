package gov.usdot.cv.security.cert;

import java.util.Date;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.Certificate;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.CertificateType;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.ToBeSignedCertificate;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.CrlSeries;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.HashedId8;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.PublicEncryptionKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.PublicVerificationKey;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Signature;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.SymmAlgorithm;
import gov.usdot.cv.security.clock.ClockHelper;
import gov.usdot.cv.security.crypto.CryptoHelper;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.util.Ieee1609dot2Helper;
import gov.usdot.cv.security.util.Time32Helper;

/**
 * Wrapper for IEEE Std 1609.2-2016 Certificate (6.4.2)
 */
public class CertificateWrapper {
	
	private static final Logger log = Logger.getLogger(CertificateWrapper.class);
	
	protected ECPublicKeyParameters encryptionPublicKey;
	protected ECPrivateKeyParameters encryptionPrivateKey;
	protected ECPublicKeyParameters signingPublicKey;
	protected ECPrivateKeyParameters signingPrivateKey;
	protected byte[] privateKeyReconstructionValueBytes;
	protected byte[] seedPrivateKeyBytes;
	protected Date expiration;
	protected Date startValidity;
	protected Certificate certificate;
	
   static private String rootPublicCertificateFriendlyName = "root";
   static private String ecaPublicCertificateFriendlyName = "ECA";
   static private String raPublicCertificateFriendlyName = "RA";
   static private String enrollmentPublicCertificateFriendlyName = "enrollment";
   private static String selfCertificateFriendlyName  = "Self";

	
	protected final CryptoProvider cryptoProvider;
	protected final CryptoHelper cryptoHelper;
	
	private static CertificateWrapper rootPublicCertificate;

	/**
	 * Instantiates empty certificate wrapper with new cryptographic provider
	 */
	protected CertificateWrapper() {
		this(null);
	}
	
	/**
	 * Instantiates empty certificate wrapper
	 * @param cryptoProvider cryptographic provider to use
	 */
	protected CertificateWrapper(CryptoProvider cryptoProvider) {
		if ( cryptoProvider == null  )
			cryptoProvider = new CryptoProvider();
		this.cryptoProvider = cryptoProvider;
		this.cryptoHelper = new CryptoHelper(cryptoProvider);
	}
	
	/**
	 * Instantiates certificate wrapper from a specified certificate to wrap
	 * @param cryptoProvider cryptographic provider to use
	 * @param certificate certificate to wrap
	 * @throws CertificateException on certificate error
	 * @throws EncodeNotSupportedException on non-supported encoding
	 * @throws EncodeFailedException encoding error
	 */
	protected CertificateWrapper(CryptoProvider cryptoProvider, Certificate certificate) 
																	throws CertificateException, EncodeFailedException, EncodeNotSupportedException {
		this(cryptoProvider);
		wrap(certificate, null, null);
	}
	
	/**
	 * Instantiates certificate wrapper from encoded certificate bytes
	 * @param cryptoProvider cryptographic provider to use
	 * @param certificateBytes encoded bytes of the certificate to wrap
	 * @param privateKeyReconstructionValueBytes private key reconstruction value bytes used in private key reconstruction
	 * @param seedPrivateKeyBytes seed private key bytes used in private key reconstruction
	 * @throws CertificateException on certificate error
	 * @throws EncodeNotSupportedException on non-supported encoding
	 * @throws EncodeFailedException encoding error 
	 */
	protected CertificateWrapper(CryptoProvider cryptoProvider, byte[] certificateBytes,
									byte[] privateKeyReconstructionValueBytes, byte[] seedPrivateKeyBytes)
																	throws CertificateException, EncodeFailedException, EncodeNotSupportedException {
		this(cryptoProvider);
		Certificate decodedCert = decode(certificateBytes);
		wrap(decodedCert, privateKeyReconstructionValueBytes, seedPrivateKeyBytes);
	}
	
	/**
	 * Creates certificate wrapper from existing certificate
	 * @param cryptoProvider cryptographic provider to use
	 * @param certificate certificate to wrap
	 * @return decoded and wrapped certificate
	 * @throws CertificateException on certificate error
	 * @throws EncodeNotSupportedException on non-supported encoding
	 * @throws EncodeFailedException encoding error
	 */
	static public CertificateWrapper fromCertificate(CryptoProvider cryptoProvider, Certificate certificate)
																	throws CertificateException, EncodeFailedException, EncodeNotSupportedException {
		return new CertificateWrapper(cryptoProvider, certificate);
	}
	
	/**
	 * Creates certificate wrapper from encoded byte array
	 * @param cryptoProvider cryptographic provider to use
	 * @param certificateBytes encoded byte array to decode certificate from
	 * @return decoded and wrapped certificate
	 * @throws CertificateException on certificate error
	 * @throws EncodeNotSupportedException on non-supported encoding
	 * @throws EncodeFailedException encoding error
	 */
	static public CertificateWrapper fromBytes(CryptoProvider cryptoProvider, byte[] certificateBytes)
																	throws CertificateException, EncodeFailedException, EncodeNotSupportedException {
		return new CertificateWrapper(cryptoProvider, certificateBytes, null, null);
	}
		
	/**
	 * Creates certificate wrapper from encoded byte array
	 * @param cryptoProvider cryptographic provider to use
	 * @param certificateBytes encoded byte array to decode certificate from
	 * @param privateKeyReconstructionValueBytes private key reconstruction value bytes used in private key reconstruction
	 * @param seedPrivateKeyBytes seed private key bytes used in private key reconstruction
	 * @return decoded and wrapped certificate
	 * @throws CertificateException on certificate error
	 * @throws EncodeNotSupportedException on non-supported encoding
	 * @throws EncodeFailedException encoding error
	 */
	static public CertificateWrapper fromBytes(CryptoProvider cryptoProvider, byte[] certificateBytes,
												byte[] privateKeyReconstructionValueBytes, byte[] seedPrivateKeyBytes) 
																	throws CertificateException, EncodeFailedException, EncodeNotSupportedException {
		return new CertificateWrapper(cryptoProvider, certificateBytes, privateKeyReconstructionValueBytes, seedPrivateKeyBytes);
	}
	
	/**
	 * Retrieves the wrapped certificate
	 * @return the wrapped certificate
	 */
	public Certificate getCertificate() {
		return certificate;
	}
	
	/**
	 * Retrieves encoded certificate bytes of the wrapped certificate
	 * @return the wrapped certificate's encoded bytes
	 */
	public byte[] getBytes() {
		byte[] certBytes = null;
		try {
			certBytes = Ieee1609dot2Helper.encodeCOER(certificate);
		} catch (EncodeFailedException | EncodeNotSupportedException e) {
			log.error("Failed to encode certificate", e);
		}
		return certBytes;
	}

	/**
	 * Retrieves public encryption key
	 * @return public encryption key or null if the key is not present in the certificate
	 * @throws EncodeNotSupportedException on non-supported encoding
	 * @throws EncodeFailedException encoding error
	 */
	public final ECPublicKeyParameters getEncryptionPublicKey() throws EncodeFailedException, EncodeNotSupportedException {
		return encryptionPublicKey;
	}
	
	/**
	 * Assigns new public encryption key
	 * @param encryptionPublicKey public encryption key value
	 */
	public void setEncryptionPublicKey(ECPublicKeyParameters encryptionPublicKey) {
		this.encryptionPublicKey = encryptionPublicKey;
	}

	/**
	 * Retrieves private encryption key
	 * @return private encryption key or null if the key is not present in the certificate
	 */
	public final ECPrivateKeyParameters getEncryptionPrivateKey() {
		return encryptionPrivateKey;
	}
	
	/**
	 * Assigns new private encryption key
	 * @param encryptionPrivateKey new private encryption key value
	 */
	public void setEncryptionPrivateKey(ECPrivateKeyParameters encryptionPrivateKey) {
		this.encryptionPrivateKey = encryptionPrivateKey;
	}

	/**
	 * Retrieves public signing key
	 * @return public signing key or null if the key is not present in the certificate
	 */
	public final ECPublicKeyParameters getSigningPublicKey() {
		return signingPublicKey;
	}
	
	/**
	 * Assigns new public signing key
	 * @param signingPublicKey new public signing key value
	 */
	public void setSigningPublicKey(ECPublicKeyParameters signingPublicKey) {
		this.signingPublicKey = signingPublicKey;
	}

	/**
	 * Retrieves private signing key
	 * @return private signing key or null if the key is not present in the certificate
	 */
	public final ECPrivateKeyParameters getSigningPrivateKey() {
		return signingPrivateKey;
	}

	/**
	 * Assigns new private signing key
	 * @param signingPrivateKey new private signing key value
	 */
	public void setSigningPrivateKey(ECPrivateKeyParameters signingPrivateKey) {
		this.signingPrivateKey = signingPrivateKey;
		
	}

	/**
	 * Verifies that certificate is valid i.e. start date is valid, not expired, and not revoked
	 * @return true if the certificate is valid and false otherwise
	 */
	public boolean isValid() {
		Date now = ClockHelper.nowDate();
		// start date is valid
		if (startValidity != null && !startValidity.before(now)) {
			log.info(String.format("The certificate will become valid on %s", startValidity));
			return false;
		}
		// not expired
		if (!expiration.after(now)) {
			log.error("The certificate had expired on " + expiration);
			return false;
		}
		// not revoked
		if (CertificateManager.isRevoked(this)) {
			log.error("The certificate was revoked");
			return false;
		}
		return true;
	}

	/**
	 * Retrieves expiration date for the certificate
	 * @return expiration date
	 */
	public Date getExpiration() {
		return expiration;
	}

	/**
	 * Retrieves certificate HashedId8 (a.k.a. digest) which is the low-order 8 octets of
	 * the hash of that certificate obtained using SHA-256 as specified in the FIPS 180-3 
	 * @return 8 byte certificate digest
	 */
	public HashedId8 getCertID8() {
		HashedId8 certID8 = null;
		
		byte[] bytes = getBytes();
		if(bytes != null) {
			byte[] digest = cryptoHelper.computeDigest(bytes);
			if (digest != null) {
				byte[] certID8Bytes = new byte[8];
				System.arraycopy(digest,  digest.length - 8, certID8Bytes, 0, 8);
				certID8 = new HashedId8(certID8Bytes);
			}
		}
		
		return certID8;
	}
	
	/**
	 * Returns HEX representation of the encoded certificate's bytes
	 */
	@Override
	public String toString() {
		return Hex.encodeHexString(getBytes());
	}
	
	/**
	 * Decodes encoded certificate bytes
	 * @param certBytes the encoded certificate bytes
	 * @throws CertificateException
	 */
	private Certificate decode(byte[] certBytes) throws CertificateException {
		try {
			return Ieee1609dot2Helper.decodeCOER(certBytes, new Certificate());
		} catch (DecodeFailedException | DecodeNotSupportedException e) {
			throw new CertificateException("Failed to decode certificate bytes: " + Hex.encodeHexString(certBytes), e);
		}
		
	}
	
	/**
	 * Wraps a certificate
	 * @param certificate  the certificate to wrap
	 * @param privateKeyReconstructionValueBytes  private key reconstruction value bytes used in private key reconstruction
	 * @param seedPrivateKeyBytews  seed private key bytes used in private key reconstruction
	 * @throws CertificateException
	 * @throws EncodeFailedException
	 * @throws EncodeNotSupportedException
	 */
	private void wrap(Certificate certificate, byte[] privateKeyReconstructionValueBytes, byte[] seedPrivateKeyBytes)
																	throws CertificateException, EncodeFailedException, EncodeNotSupportedException {
		this.certificate = certificate;
		
		ToBeSignedCertificate toBeSigned = certificate.getToBeSigned();
		
		CertificateType certType = certificate.getType();
		if(certType != CertificateType.explicit && certType != CertificateType.implicit) {
			throw new CertificateException(
							String.format(
									"Unexpected certificate version and type value %d. Supported values are: %d (explicit) and %d (implicit).", 
										certType.longValue(),
										CertificateType.explicit.longValue(),
										CertificateType.implicit.longValue()));
		}
		
		startValidity = Time32Helper.time32ToDate(toBeSigned.getValidityPeriod().getStart());

		expiration = Time32Helper.calculateEndDate(toBeSigned.getValidityPeriod());
		Date now = ClockHelper.nowDate();
		if(expiration.before(now)) {
			log.error(String.format("The certificate had expired on %s", expiration));
			throw new CertificateException(String.format("The certificate had expired on %s", expiration));
		}

		CrlSeries crlSeries = toBeSigned.getCrlSeries();
		log.debug("CrlSeries: " + crlSeries.intValue());

		ECDSAProvider ecdsaProvider = this.cryptoProvider.getSigner();

		// If the certificate is explicit & Self signed, it is a root certificate
		boolean isRootCA = (certType == CertificateType.explicit) && (certificate.getIssuer().hasSelf());
		
		CertificateWrapper signerCertificate = null;
		if(isRootCA) {
			signerCertificate = this;
		}
		else {
			HashedId8 signerCertId8 = certificate.getIssuer().getSha256AndDigest();
			log.debug("Signer CertId8: " + Hex.encodeHexString(signerCertId8.byteArrayValue()));
			
			signerCertificate = getSignerCertificate(signerCertId8);
		}
		
		if(certType == CertificateType.explicit) {
			// Explicit certs include the signing public key, so grab it
			PublicVerificationKey verificationKey = toBeSigned.getVerifyKeyIndicator().getVerificationKey();
			EccP256CurvePoint verificationKeyPoint = (verificationKey.hasEcdsaNistP256()) ?
															(verificationKey.getEcdsaNistP256()) :
															(verificationKey.getEcdsaBrainpoolP256r1());
			signingPublicKey = ecdsaProvider.decodePublicKey(verificationKeyPoint);

			/*// TODO: Turn back on verification of signature when we are able to test with valid certs
			// Decode and verify signature
			EcdsaP256SignatureWrapper signature = EcdsaP256SignatureWrapper.decode(certificate.getSignature(), ecdsaProvider);
			byte[] tbsBytes = Ieee1609dot2Helper.encodeCOER(toBeSigned);
			if (!cryptoHelper.verifySignature(tbsBytes, signerCertificate.getBytes(), signerCertificate.getSigningPublicKey(), signature)) {
				throw new CertificateException("Certificate signature is not valid");
			}*/
		}
		else {
		    if (signerCertificate.getCertificate().getToBeSigned().getVerifyKeyIndicator().hasReconstructionValue()) {
   			// Reconstruct the Signing Public Key
   			signingPublicKey = ecdsaProvider.reconstructImplicitPublicKey(signerCertificate, this);
		    }
		}

		// Grab or reconstruct the Encryption Public Key
		if(toBeSigned.hasEncryptionKey()) {
			PublicEncryptionKey encryptionKey = toBeSigned.getEncryptionKey();
			
			if(!encryptionKey.getSupportedSymmAlg().equalTo(SymmAlgorithm.aes128Ccm)) {
				throw new CertificateException("Unexpected public key algorithm value: " + encryptionKey.getSupportedSymmAlg());
			}
			
			EccP256CurvePoint encryptionKeyPoint = (encryptionKey.getPublicKey().hasEciesNistP256()) ?
															(encryptionKey.getPublicKey().getEciesNistP256()) :
															(encryptionKey.getPublicKey().getEciesBrainpoolP256r1());
															
			encryptionPublicKey = ecdsaProvider.decodePublicKey(encryptionKeyPoint);
		}
		else {
         if (signerCertificate.getCertificate().getToBeSigned().getVerifyKeyIndicator().hasReconstructionValue()) {
            encryptionPublicKey = ecdsaProvider.reconstructImplicitPublicKey(signerCertificate, this);
         }
		}

		// Reconstruct Private Encryption and Signing Keys
		if(privateKeyReconstructionValueBytes != null && seedPrivateKeyBytes != null) {
			// Reconstruct Private Encryption Key
			encryptionPrivateKey = ecdsaProvider.reconstructImplicitPrivateKey(
																	signerCertificate,
																	this,
																	privateKeyReconstructionValueBytes,
																	seedPrivateKeyBytes);

			// Reconstruct the Signing Private Key
			signingPrivateKey = ecdsaProvider.reconstructImplicitPrivateKey(
																	signerCertificate,
																	this,
																	privateKeyReconstructionValueBytes,
																	seedPrivateKeyBytes);
		}
	}
	
	/**
	 * Finds signer certificate by digest
	 * @param signerCertId8 singer digest
	 * @return signer certificate
	 */
	private CertificateWrapper getSignerCertificate (HashedId8 signerCertId8) {
		CertificateWrapper signerCertificate = null;
		if (signerCertId8 != null) {
			signerCertificate = CertificateManager.get(signerCertId8);
		}
		if (signerCertificate == null) {
			String id = (signerCertId8 == null)?("null"):(Hex.encodeHexString(signerCertId8.byteArrayValue()));
			log.warn("Signer certificate with CertId8 " + id +
						" not found in the certificate store. Falling back for root CA");
			signerCertificate = getRootPublicCertificate();
		}
		return signerCertificate;
	}
	
	/**
	 * Retrieves certificate's signing certificate instance
	 * @return certificate's signing certificate
	 */
	static private CertificateWrapper getRootPublicCertificate() {
		if ( rootPublicCertificate == null ) {
			synchronized(Certificate.class) {
				if ( rootPublicCertificate == null )
					rootPublicCertificate = CertificateManager.get(rootPublicCertificateFriendlyName);
			}
		}
		return rootPublicCertificate;
	}
	
	/**
	 * Retrieves a friendly name of the certificate's signing certificate 
	 * @return certificate's friendly name
	 */
	public static String getRootPublicCertificateFriendlyName() {
		return rootPublicCertificateFriendlyName;
	}

	/**
	 * Assigns a new friendly name of the certificate signing certificate
	 * @param newRootPublicCertificateFriendlyName new friendly name 
	 */
	public static void setRootPublicCertificateFriendlyName(String newRootPublicCertificateFriendlyName) {
		rootPublicCertificateFriendlyName = newRootPublicCertificateFriendlyName;
	}
	
	public static String getEcaPublicCertificateFriendlyName() {
      return ecaPublicCertificateFriendlyName;
   }

   public static void setEcaPublicCertificateFriendlyName(String ecaPublicCertificateFriendlyName) {
      CertificateWrapper.ecaPublicCertificateFriendlyName = ecaPublicCertificateFriendlyName;
   }

   public static String getRaPublicCertificateFriendlyName() {
      return raPublicCertificateFriendlyName;
   }

   public static void setRaPublicCertificateFriendlyName(String raPublicCertificateFriendlyName) {
      CertificateWrapper.raPublicCertificateFriendlyName = raPublicCertificateFriendlyName;
   }

   public static String getEnrollmentPublicCertificateFriendlyName() {
      return enrollmentPublicCertificateFriendlyName;
   }

   public static void setEnrollmentPublicCertificateFriendlyName(String enrollmentPublicCertificateFriendlyName) {
      CertificateWrapper.enrollmentPublicCertificateFriendlyName = enrollmentPublicCertificateFriendlyName;
   }

   public static String getSelfCertificateFriendlyName() {
      return selfCertificateFriendlyName;
   }

   public static void setSelfCertificateFriendlyName(String selfCertificateFriendlyName) {
      CertificateWrapper.selfCertificateFriendlyName = selfCertificateFriendlyName;
   }

   /**
     * Return the certificate bytes without a signature included.
     * @param cert  certificate to retrieve the unsigned data from
     * @param certBytes  the encoded certificate bytes
     * @return  a byte array of the certificate without the signature
     */
    private static byte[] getUnsignedDataBytes(final Certificate cert, final byte[] certBytes) {
    	byte[] unsignedData = null;
    	
    	if(cert.hasSignature()) {
    		// Grab the signature from the certificate
    		Signature signature = cert.getSignature();
    		
    		// Encode it to get it's form as
    		try {
				byte[] signatureBytes = Ieee1609dot2Helper.encodeCOER(signature);
				
				// Per the standard, the signature is always at the end of the 
				// certificate, so we can just copy the certificate bytes minus
				// the length of the signature
				int unsignedDataLength = certBytes.length - signatureBytes.length;
				unsignedData = new byte[unsignedDataLength];
				System.arraycopy(certBytes, 0, unsignedData, 0, unsignedDataLength);
			} catch (EncodeFailedException | EncodeNotSupportedException e) {
				log.error("Failed to encode signature when calculating unsigned data.", e);
			}
    	}
    	
    	return unsignedData;
    }
}
