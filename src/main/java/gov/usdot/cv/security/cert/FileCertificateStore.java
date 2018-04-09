package gov.usdot.cv.security.cert;

import java.io.IOException;
import java.nio.file.Path;

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
	 * @param certFilePath certificate file path
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
	public static boolean load(CryptoProvider cryptoProvider, String name, Path certFilePath) 
														throws CertificateException {
		return load(cryptoProvider, name, certFilePath, null, null);
	}
	
	/**
	 * Loads encrypted certificate from file
	 * @param cryptoProvider cryptographic provider to use
	 * @param name friendly certificate name
	 * @param certificateFilePath certificate file path
	 * @param privateKeyReconstructionFilePath private key reconstruction value file path
	 * @param seedPrivateKey the seed private key stored in the keystore
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
	public static boolean load(CryptoProvider cryptoProvider, String name, Path certificateFilePath,
	   Path privateKeyReconstructionFilePath, SecureECPrivateKey seedPrivateKey) throws CertificateException 
	{
		try {
         String msg = String.format("Loading certificate %s from file '%s'", name, certificateFilePath);
         log.info(msg);
         
         byte[] certificateBytes = null;
         try {
         	certificateBytes = FileUtils.readFileToByteArray(certificateFilePath.toFile());
         } catch (Exception ex ) {
         	throw new CertificateException("Coulnd't read file '" + certificateFilePath + "'. Reason: " + ex.getMessage(), ex);
         }
         
         byte[]  privateKeyReconstructionValueBytes = null;
         if(privateKeyReconstructionFilePath != null) {
            try {
               privateKeyReconstructionValueBytes = FileUtils.readFileToByteArray(privateKeyReconstructionFilePath.toFile());
            } catch (Exception ex ) {
               throw new CertificateException("Coulnd't read file '" + privateKeyReconstructionFilePath + "'. Reason: " + ex.getMessage(), ex);
            }
         }
         
         return load(cryptoProvider, name, certificateBytes, privateKeyReconstructionValueBytes , seedPrivateKey);
      } catch (Exception e) {
         throw new CertificateException("Error loading certificate from " + certificateFilePath, e);
      }
	}
	
   /**
    * Loads certificate bytes
    * @param cryptoProvider cryptographic provider to use
    * @param name friendly certificate name
    * @param certificateBytes certificate bytes
    * @param privateKeyReconstructionValueBytes private key reconstruction value bytes
    * @param seedPrivateKey the seed private key stored in the keystore
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
   public static boolean load(CryptoProvider cryptoProvider, String name, byte[] certificateBytes,
      byte[] privateKeyReconstructionValueBytes, SecureECPrivateKey seedPrivateKey) throws CertificateException 
   {
      try {
         String msg = String.format("Loading certificate %s ", name);
         CertificateWrapper cert;
         
         boolean success = false;
         if(privateKeyReconstructionValueBytes == null) {
            cert = CertificateWrapper.fromBytes(cryptoProvider, certificateBytes);
            success = true;
         } else {
            msg += " using private key reconstruction value and secret seed private key";

            cert = CertificateWrapper.fromBytes(cryptoProvider, certificateBytes, 
               privateKeyReconstructionValueBytes, seedPrivateKey);
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
             success = true;
            }
         }
         
         if (success)
            log.warn(msg + " was unsuccessful.");
         else
            log.debug(msg + " FAILED.");
         
         return success;
      } catch (Exception e) {
         throw new CertificateException("Error loading certificate!", e);
      }
   }
}