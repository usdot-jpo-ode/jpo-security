package gov.usdot.cv.security.cert;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EciesP256EncryptedKey;
import gov.usdot.cv.security.clock.ClockHelperTest;
import gov.usdot.cv.security.crypto.AESProvider;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.crypto.ECIESProvider;
import gov.usdot.cv.security.crypto.EcdsaP256SignatureWrapper;
import gov.usdot.cv.security.util.UnitTestHelper;

@Ignore
public class CertificateWrapperTest {

    static final private boolean isDebugOutput = false;
    private static final Logger log = Logger.getLogger(CertificateWrapperTest.class);
    
    private static String certsValidDate = "Fri May 05 20:44:47 EDT 2017";
    
    private static String PcaCert = "<hex of the bytes from trustedcerts/pca file>";

    private static String SigningPrivateKey = "<hex of the bytes from sign.prv>";
    
    private static String SelfCert  = "<hex of the bytes from downloadFiles/0465676ec6d9c8c0.cert>";
    private static String SelfCertPrivateKeyReconstructionValue = "<hex of the bytes from downloadFiles/0465676ec6d9c8c0.s>";
    
    private static String ClientCert  = "<hex of the bytes from downloadFiles/1ece38c9a40bf946.cert>";
    private static String ClientCertPrivateKeyReconstructionValue = "<hex of the bytes from downloadFiles/1ece38c9a40bf946.s>";
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {	
    	loadCertsFromFile();
		CryptoProvider.initialize();
        UnitTestHelper.initLog4j(isDebugOutput);
        
		ClockHelperTest.setNow(certsValidDate);
    }
    
    public static void loadCertsFromFile() throws IOException{
    	String certsFolder = "/etc/1609_sample_certs/certs/";
    	String pcaCert = "trustedcerts/pca";
    	String signingPrivateKey = "sign.prv";
    	String selfCert = "downloadFiles/0465676ec6d9c8c0.cert";
    	String selfCertPrivateKeyReconstructionValue = "downloadFiles/0465676ec6d9c8c0.s";
    	String clientCert = "downloadFiles/1ece38c9a40bf946.cert";
    	String clientCertPrivateKeyReconstructionValue = "downloadFiles/1ece38c9a40bf946.s";
    	
    	Path path = Paths.get(certsFolder, pcaCert);
    	PcaCert = Hex.encodeHexString(Files.readAllBytes(path));
    	
    	path = Paths.get(certsFolder, signingPrivateKey);
    	SigningPrivateKey = Hex.encodeHexString(Files.readAllBytes(path));
    	
    	path = Paths.get(certsFolder, selfCert);
    	SelfCert = Hex.encodeHexString(Files.readAllBytes(path));
    	
    	path = Paths.get(certsFolder, selfCertPrivateKeyReconstructionValue);
    	SelfCertPrivateKeyReconstructionValue = Hex.encodeHexString(Files.readAllBytes(path));
    	
    	path = Paths.get(certsFolder, clientCert);
    	ClientCert = Hex.encodeHexString(Files.readAllBytes(path));
    	
    	path = Paths.get(certsFolder, clientCertPrivateKeyReconstructionValue);
    	ClientCertPrivateKeyReconstructionValue = Hex.encodeHexString(Files.readAllBytes(path));
    }
    
    @Test
    public void test()  throws DecoderException, CertificateException, IOException,
    							CryptoException, InvalidCipherTextException, DecodeFailedException,
    							DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
    	testExplicit();
    	testEncrypted("Self", SelfCert, SelfCertPrivateKeyReconstructionValue, SigningPrivateKey);
    	testEncrypted("Client", ClientCert, ClientCertPrivateKeyReconstructionValue, SigningPrivateKey);
    }
    
    public void testExplicit() throws DecoderException, CertificateException, IOException, CryptoException,
    									EncodeFailedException, EncodeNotSupportedException {
    	for(String[] cert : new String[][] {{ PcaCert, "PCA" }}) {
    		String hexCert = cert[0];
    		String name = cert[1];
    		
    		byte[] certBytes = Hex.decodeHex(hexCert.toCharArray());
        	CertificateWrapper certificate = CertificateWrapper.fromBytes(new CryptoProvider(), certBytes);
        	
        	if(certificate != null) {
        		boolean isValid = certificate.isValid();
        		log.debug("Certificate is valid: " + isValid);
        		if(isValid) {
        			CertificateManager.put(name, certificate);
        		}
        	}
    	}
    }
    
    public void testEncrypted(String name, String hexCert, String hexPrivateKeyReconstructionValue, String hexSeedPrivateKey) 
    																	throws DecoderException, CertificateException, IOException,
    																			CryptoException, InvalidCipherTextException,
    																			DecodeFailedException,DecodeNotSupportedException,
    																			EncodeFailedException, EncodeNotSupportedException {
    	CryptoProvider cryptoProvider = new CryptoProvider();
    	byte[] certBytes = Hex.decodeHex(hexCert.toCharArray());
    	byte[] privateKeyReconstructionValueBytes = Hex.decodeHex(hexPrivateKeyReconstructionValue.toCharArray());
    	byte[] seedPrivateKeyBytes = Hex.decodeHex(hexSeedPrivateKey.toCharArray());
    	CertificateWrapper certificate = CertificateWrapper.fromBytes(cryptoProvider, certBytes, privateKeyReconstructionValueBytes, seedPrivateKeyBytes);
    	if(certificate != null) {
    		boolean isValid = certificate.isValid();
    		log.debug("Certificate is valid: " + isValid);
    		if(isValid) {
    			CertificateManager.put(name + "-private", certificate);
    		}
    		
    		testSigningKeyPair(cryptoProvider, certificate);
    		testEncryptionKeyPair(cryptoProvider, certificate);

    		ECDSAProvider ecdsaProvider = cryptoProvider.getSigner();
    		
			byte[] publicCertBytes = certificate.getBytes();
			CertificateWrapper publicCert = CertificateWrapper.fromBytes(cryptoProvider, publicCertBytes);
			if ( publicCert != null ) {
				assertTrue(publicCert.isValid());
				CertificateManager.put(name + "-public", certificate);
				assertNotNull(certificate.getSigningPrivateKey());
				assertNotNull(certificate.getEncryptionPrivateKey());
				assertNull(publicCert.getSigningPrivateKey());
				assertNull(publicCert.getEncryptionPrivateKey());
				comparePublicKeys(ecdsaProvider, certificate.getSigningPublicKey(), publicCert.getSigningPublicKey());
				comparePublicKeys(ecdsaProvider, certificate.getEncryptionPublicKey(), publicCert.getEncryptionPublicKey());
			}
    	}
    }
    
    private void comparePublicKeys(ECDSAProvider ecdsaProvider, ECPublicKeyParameters publicKey1, ECPublicKeyParameters publicKey2) 
    																									throws CryptoException {
		EccP256CurvePoint encodedPublicKey1 = ecdsaProvider.encodePublicKey(publicKey1);
		EccP256CurvePoint encodedPublicKey2 = ecdsaProvider.encodePublicKey(publicKey2);
		assertTrue( "Public keys match", encodedPublicKey1.equalTo(encodedPublicKey2));
    }
    
    private void testSigningKeyPair(CryptoProvider cryptoProvider, CertificateWrapper certificate) {
    	assertNotNull(cryptoProvider);
    	assertNotNull(certificate);
    	ECDSAProvider ecdsaProvider = cryptoProvider.getSigner();
    	
		final byte[] textBytes = "Hello, World!".getBytes();

		EcdsaP256SignatureWrapper signature = ecdsaProvider.computeSignature(textBytes,  certificate.getBytes(), certificate.getSigningPrivateKey());
		boolean isSignatureValid = ecdsaProvider.verifySignature(textBytes, certificate.getBytes(), certificate.getSigningPublicKey(), signature);
		log.debug("Is Signarure Valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
    }
    
    public void testEncryptionKeyPair(CryptoProvider cryptoProvider, CertificateWrapper certificate)
    											throws InvalidCipherTextException, CryptoException,
    													EncodeFailedException, EncodeNotSupportedException {
    	assertNotNull(cryptoProvider);
    	assertNotNull(certificate);
    	
		// generate key to encrypt
		KeyParameter symmetricKey = AESProvider.generateKey();
		assertNotNull(symmetricKey);
		log.debug(Hex.encodeHexString(symmetricKey.getKey()));
		
		
		ECIESProvider eciesProvider = cryptoProvider.getECIESProvider();
		
		// encrypt and encode the key
		EciesP256EncryptedKey eciesP256EncryptedKey = eciesProvider.encodeEciesP256EncryptedKey(symmetricKey, certificate.getEncryptionPublicKey());
		
		// decode and decrypt the key
		KeyParameter symmetricKey2 = eciesProvider.decodeEciesP256EncryptedKey(eciesP256EncryptedKey, certificate.getEncryptionPrivateKey());
		assertNotNull(symmetricKey2);
		log.debug(Hex.encodeHexString(symmetricKey2.getKey()));
		
		assertTrue(Arrays.equals(symmetricKey.getKey(), symmetricKey2.getKey()));
    }
}

