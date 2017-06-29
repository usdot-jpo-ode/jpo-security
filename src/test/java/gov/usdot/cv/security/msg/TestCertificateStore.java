package gov.usdot.cv.security.msg;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;

import gov.usdot.cv.security.cert.CertificateWrapper;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.clock.ClockHelperTest;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

public class TestCertificateStore {
	
    static final private boolean isDebugOutput = false;
    private static final Logger log = Logger.getLogger(TestCertificateStore.class);
    
    private static String certsValidDate = "Fri May 05 20:44:47 EDT 2017";
    
    private static String PcaCert = "<hex of the bytes from trustedcerts/pca file>";

    private static String SigningPrivateKey = "<hex of the bytes from sign.prv>";
    
    private static String SelfCert  = "<hex of the bytes from downloadFiles/0465676ec6d9c8c0.cert>";
    private static String SelfCertPrivateKeyReconstructionValue = "<hex of the bytes from downloadFiles/0465676ec6d9c8c0.s>";
    
    private static String ClientCert  = "<hex of the bytes from downloadFiles/1ece38c9a40bf946.cert>";
    private static String ClientCertPrivateKeyReconstructionValue = "<hex of the bytes from downloadFiles/1ece38c9a40bf946.s>";
    
	public static void load() throws ParseException, DecoderException, CertificateException, IOException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
		loadCertsFromFile();
		CryptoProvider.initialize();
        UnitTestHelper.initLog4j(isDebugOutput);
        
		ClockHelperTest.setNow(certsValidDate);
		
		CryptoProvider cryptoProvider = new CryptoProvider();
		
		String[] names = { "PCA", "Self", "Client" };
		for( String name : names )
			if ( !load(cryptoProvider, name) )
				throw new CertificateException("Couldn't load certificate named " + name);
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
	
	public static boolean load(CryptoProvider cryptoProvider, String name) throws DecoderException, CertificateException, IOException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
		if ( name == null )
			return false;
		if ( name.equals("PCA") )
			return load(cryptoProvider, "PCA", PcaCert);
		if ( name.equals("Self") )
			return load(cryptoProvider, "Self", SelfCert, SelfCertPrivateKeyReconstructionValue, SigningPrivateKey);
		if ( name.equals("Client") )
			return load(cryptoProvider, "Client", ClientCert, ClientCertPrivateKeyReconstructionValue, SigningPrivateKey);
		return false;
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name, String hexCert) throws DecoderException, CertificateException, IOException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
    	return load(cryptoProvider, name, hexCert, null, null);
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name, String hexCert,
								String hexPrivateKeyReconstructionValue, String hexSigningPrivateKey)
										throws CertificateException, IOException, DecoderException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
    	byte[] certBytes = Hex.decodeHex(hexCert.toCharArray());
    	CertificateWrapper cert;
    	if ( hexPrivateKeyReconstructionValue == null && hexSigningPrivateKey == null ) {
    		cert = CertificateWrapper.fromBytes(cryptoProvider, certBytes);
    	} else {
	    	byte[] privateKeyReconstructionValueBytes = Hex.decodeHex(hexPrivateKeyReconstructionValue.toCharArray());
	    	byte[] signingPrivateKeyBytes = Hex.decodeHex(hexSigningPrivateKey.toCharArray());
	    	cert = CertificateWrapper.fromBytes(cryptoProvider, certBytes, privateKeyReconstructionValueBytes, signingPrivateKeyBytes);
    	}
    	if ( cert != null ) {
    		boolean isValid = cert.isValid();
    		log.debug("Certificate is valid: " + isValid);
    		if ( isValid )
    			CertificateManager.put(name, cert);
    		return isValid;
    	}
    	return false;
	}
}
