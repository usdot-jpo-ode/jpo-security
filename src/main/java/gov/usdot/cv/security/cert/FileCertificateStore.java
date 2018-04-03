package gov.usdot.cv.security.cert;

import java.io.IOException;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

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
		return load(cryptoProvider, name, certFilePath, null);
	}
	
	/**
	 * Loads encrypted certificate from file
	 * @param cryptoProvider cryptographic provider to use
	 * @param name friendly certificate name
	 * @param certificateFilePath certificate file path
	 * @param privateKeyReconstructionFilePath private key reconstruction value file path
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
	                           Path privateKeyReconstructionFilePath) throws CertificateException 
														 {
		try {
         CertificateWrapper cert;
         String msg = String.format("Loading certificate %s from file '%s'", name, certificateFilePath);

         byte[] certificateBytes = null;
         try {
         	certificateBytes = FileUtils.readFileToByteArray(certificateFilePath.toFile());
         } catch (Exception ex ) {
         	throw new CertificateException("Coulnd't read file '" + certificateFilePath + "'. Reason: " + ex.getMessage(), ex);
         }
         
         /*
          * TODO: The seed private key cannot be stored in a file. 
          * The following code must be updated to use the HSM or a keystore
          * 
          */
         boolean success = false;
         if(privateKeyReconstructionFilePath == null  
               //TODO && seedPrivateKeyFilePath == null
               ) {
         	cert = CertificateWrapper.fromBytes(cryptoProvider, certificateBytes);
         	success = true;
         } else {
//         	msg += " using private key reconstruction value file '" +  privateKeyReconstructionFilePath + "'";
//         	msg += " and seed private key file '" + seedPrivateKeyFilePath + "'";
//         	
//         	byte[]  privateKeyReconstructionValueBytes = null;
//         	try {
//         		privateKeyReconstructionValueBytes = FileUtils.readFileToByteArray(privateKeyReconstructionFilePath.toFile());
//         	} catch (Exception ex ) {
//         		throw new CertificateException("Coulnd't read file '" + privateKeyReconstructionFilePath + "'. Reason: " + ex.getMessage(), ex);
//         	}
//         	
//
//         	byte[] seedPrivateKeyBytes = null;
//         	try {
//         		seedPrivateKeyBytes = FileUtils.readFileToByteArray(seedPrivateKeyFilePath.toFile());
//         	} catch (Exception ex ) {
//         		throw new CertificateException("Coulnd't read file '" + seedPrivateKeyFilePath + "'. Reason: " + ex.getMessage(), ex);
//         	}
//         	
//         	cert = CertificateWrapper.fromBytes(cryptoProvider, certificateBytes, privateKeyReconstructionValueBytes, seedPrivateKeyBytes);
//         }
//         
//         if(cert != null) {
//         	HashedId8 certId8 = cert.getCertID8();
//         	if(certId8 == null) {
//         		throw new CertificateException("certId8 cannot be empty for certificate " + name);
//         	}
//         	msg += ". CertId8: " + Hex.encodeHexString(certId8.byteArrayValue());
//         	boolean isValid = cert.isValid();
//         	msg += ". Certificate is valid: " + isValid;
//         	if(isValid) {
//         		CertificateManager.put(name, cert);
//             success = true;
//         	}
         }
         
         if (success)
            log.debug(msg + " was unsuccessful.");
         else
            log.debug(msg + " FAILED.");
         
         return success;
      } catch (Exception e) {
         throw new CertificateException("Error loading certificate from " + certificateFilePath, e);
      }
	}
	
   /**
    * Loads encrypted certificate from zip file input stream
    * @param cryptoProvider cryptographic provider to use
    * @param name friendly certificate name
    * @param zipEntry zip entry
    * @param zis zip file input stream
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
   public static boolean load(CryptoProvider cryptoProvider, String name, ZipEntry zipEntry, ZipInputStream zis) throws CertificateException 
                                           {
      try{
         int bufferSize = (int) zipEntry.getSize();
         byte[] certificateBytes = new byte[bufferSize];
         boolean success = false;
         while (zis.read(certificateBytes) > 0) {
            
            CertificateWrapper cert;
            String msg = String.format("Loading certificate %s from file '%s'", name, zipEntry.getName());
            /*
             * TODO: The seed private key cannot be stored in a file. 
             * The following code must be updated to use the HSM or a keystore
             * Also the private key reconstruction value needs to be read from
             * the zip input stream 
             * 
             */
          //TODO if (privateKeyReconstructionFilePath == null  && seedPrivateKeyFilePath == null) {
               cert = CertificateWrapper.fromBytes(cryptoProvider, certificateBytes);
               success = true;
//            } else {
//               msg += " using private key reconstruction value file '" +  privateKeyReconstructionFilePath + "'";
//               msg += " and seed private key file '" + seedPrivateKeyFilePath + "'";
//               
//               byte[]  privateKeyReconstructionValueBytes = null;
//               try {
//                  privateKeyReconstructionValueBytes = FileUtils.readFileToByteArray(privateKeyReconstructionFilePath.toFile());
//               } catch (Exception ex ) {
//                  throw new CertificateException("Coulnd't read file '" + privateKeyReconstructionFilePath + "'. Reason: " + ex.getMessage(), ex);
//               }
//               
//
//               byte[] seedPrivateKeyBytes = null;
//               try {
//                  seedPrivateKeyBytes = FileUtils.readFileToByteArray(seedPrivateKeyFilePath.toFile());
//               } catch (Exception ex ) {
//                  throw new CertificateException("Coulnd't read file '" + seedPrivateKeyFilePath + "'. Reason: " + ex.getMessage(), ex);
//               }
//               
//               cert = CertificateWrapper.fromBytes(cryptoProvider, certificateBytes, privateKeyReconstructionValueBytes, seedPrivateKeyBytes);
//            }
//            
//            if(cert != null) {
//               HashedId8 certId8 = cert.getCertID8();
//               if(certId8 == null) {
//                  throw new CertificateException("certId8 cannot be empty for certificate " + name);
//               }
//               msg += ". CertId8: " + Hex.encodeHexString(certId8.byteArrayValue());
//               boolean isValid = cert.isValid();
//               msg += ". Certificate is valid: " + isValid;
//               if(isValid) {
//                  CertificateManager.put(name, cert);
//                success = true;
//               }
//            }
            
            if (success)
               log.debug(msg + " was unsuccessful.");
            else
               log.debug(msg + " FAILED.");
         }
         return success;
      } catch (Exception e) {
         throw new CertificateException("Error loading certificate from " + zipEntry, e);
      }
   }
}