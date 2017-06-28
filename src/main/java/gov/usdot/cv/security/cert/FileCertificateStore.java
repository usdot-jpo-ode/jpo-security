package gov.usdot.cv.security.cert;

import java.io.File;
import java.io.IOException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.HashedId8;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;

/**
 * Helper class to load a certificates stored on the file system
 *
 */
public class FileCertificateStore {
	
	private static final Logger log = Logger.getLogger(FileCertificateStore.class);
	
	/**
	 * Loads public certificate from file
	 * @param cryptoProvider cryptographic provider to use
	 * @param name friendly certificate name
	 * @param certFileName certificate file path
	 * @return true if certificate was added to the CertificateManager and false otherwise
	 * @throws DecoderException if HEX string decoding fails
	 * @throws CertificateException if certificate decoding fails
	 * @throws IOException if certificate file read fails
	 * @throws CryptoException if certificate file decryption fails
	 * @throws DecodeNotSupportedException if decoding is not supported
	 * @throws DecodeFailedException if decoding failed
	 * @throws EncodeNotSupportedException if encoding is not supported
	 * @throws EncodeFailedException if encoding failed
	 */
	public static boolean load(CryptoProvider cryptoProvider, String name, String certFileName) 
														throws DecoderException, CertificateException, IOException,
															   CryptoException, DecodeFailedException, DecodeNotSupportedException,
															   EncodeFailedException, EncodeNotSupportedException {
		return load(cryptoProvider, name, certFileName, null, null);
	}
	
	/**
	 * Loads encrypted certificate from file
	 * @param cryptoProvider cryptographic provider to use
	 * @param name friendly certificate name
	 * @param certificateFileName certificate file path
	 * @param privateKeyReconstructionFileName private key reconstruction value file path
	 * @param seedPrivateKeyFileName seed private key file path
	 * @return true if certificate was added to the CertificateManager and false otherwise
	 * @throws DecoderException if HEX string decoding fails
	 * @throws CertificateException if certificate decoding fails
	 * @throws IOException if certificate file read fails
	 * @throws CryptoException if certificate file decryption fails
	 * @throws DecodeNotSupportedException if decoding is not supported
	 * @throws DecodeFailedException if decoding failed
	 * @throws EncodeNotSupportedException if encoding is not supported
	 * @throws EncodeFailedException if encoding failed 
	 */
	public static boolean load(CryptoProvider cryptoProvider, String name, String certificateFileName,
									String privateKeyReconstructionFileName, String seedPrivateKeyFileName) 
														throws CertificateException, IOException, DecoderException,
															   CryptoException, DecodeFailedException, DecodeNotSupportedException,
															   EncodeFailedException, EncodeNotSupportedException {
		byte[] certificateBytes = null;
		try {
			certificateBytes = FileUtils.readFileToByteArray(new File(certificateFileName));
		} catch (Exception ex ) {
			log.error("Coulnd't read file '" + certificateFileName + "'. Reason: " + ex.getMessage(), ex);
		}
		
		CertificateWrapper cert;
		String msg = String.format("Loading certificate %s from file '%s'", name, certificateFileName);
		if(privateKeyReconstructionFileName == null  && seedPrivateKeyFileName == null) {
			cert = CertificateWrapper.fromBytes(cryptoProvider, certificateBytes);
		} else {
			msg += " using private key reconstruction value file '" +  privateKeyReconstructionFileName + "'";
			msg += " and seed private key file '" + seedPrivateKeyFileName + "'";
			
			byte[]  privateKeyReconstructionValueBytes = null;
			try {
				privateKeyReconstructionValueBytes = FileUtils.readFileToByteArray(new File(privateKeyReconstructionFileName));
			} catch (Exception ex ) {
				log.error("Coulnd't read file '" + privateKeyReconstructionFileName + "'. Reason: " + ex.getMessage(), ex);
			}
			

			byte[] seedPrivateKeyBytes = null;
			try {
				seedPrivateKeyBytes = FileUtils.readFileToByteArray(new File(seedPrivateKeyFileName));
			} catch (Exception ex ) {
				log.error("Coulnd't read file '" + seedPrivateKeyFileName + "'. Reason: " + ex.getMessage(), ex);
			}
			
			cert = CertificateWrapper.fromBytes(cryptoProvider, certificateBytes, privateKeyReconstructionValueBytes, seedPrivateKeyBytes);
		}
		
		if(cert != null) {
			HashedId8 certId8 = cert.getCertID8();
			if(certId8 == null) {
				throw new CertificateException("certId8 cannot be empty for certificate " + name);
			}
			msg += ". CertId8: " + Hex.encodeHexString(certId8.byteArrayValue());
			boolean isValid = cert.isValid();
			msg += ". Certificate is valid: " + isValid;
			if(isValid) {
				CertificateManager.put(name, cert);
			}
			log.debug(msg);
			return isValid;
		}
		
		log.debug(msg + " was unsuccessful.");
		return false;
	}
	
}
